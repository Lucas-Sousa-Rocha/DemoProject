package com.quantum.demoproject.security;

import com.quantum.demoproject.Service.TokenService;
import com.quantum.demoproject.model.UserEntity;
import com.quantum.demoproject.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtService jwtService;
    private final UserRepository userRepo;
    private final TokenService tokenService;

    private final RequestMatcher skipAuthEndpoints = request ->
            request.getRequestURI().startsWith("/auth/login") ||
                    request.getRequestURI().startsWith("/auth/register") ||
                    request.getRequestURI().startsWith("/auth/refresh") ||
                    request.getRequestURI().startsWith("/h2-console");

    public JwtAuthFilter(JwtService jwtService, UserRepository userRepo, TokenService tokenService) {
        this.jwtService = jwtService;
        this.userRepo = userRepo;
        this.tokenService = tokenService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return skipAuthEndpoints.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
            logger.debug("Nenhum token válido encontrado no header Authorization");
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            String username = jwtService.getSubject(token);
            logger.debug("Token JWT recebido para usuário: {}", username);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserEntity user = userRepo.findByUsername(username)
                        .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

                // 🔹 Verifica se o token é o último válido (sessão única)
                if (!tokenService.isTokenValid(user.getId(), token)) {
                    logger.warn("Token antigo detectado para usuário: {}", username);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Sessão expirada. Faça login novamente.\"}");
                    return;
                }

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authToken);
                logger.debug("Autenticação configurada no SecurityContext para: {}", user.getUsername());
            }

        } catch (Exception ex) {
            logger.error("Falha na autenticação JWT: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"" + ex.getMessage() + "\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
