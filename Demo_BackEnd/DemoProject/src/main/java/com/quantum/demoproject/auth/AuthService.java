package com.quantum.demoproject.auth;

import com.quantum.demoproject.DTO.*;
import com.quantum.demoproject.Mail.EmailService;
import com.quantum.demoproject.Service.TokenService;
import com.quantum.demoproject.model.RoleEntity;
import com.quantum.demoproject.model.UserEntity;
import com.quantum.demoproject.repository.PasswordResetTokenRepository;
import com.quantum.demoproject.repository.RoleRepository;
import com.quantum.demoproject.repository.UserRepository;
import com.quantum.demoproject.security.JwtService;
import jakarta.transaction.Transactional;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
public class AuthService {
    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authManager;
    private final JwtService jwt;
    private final PasswordResetTokenRepository resetRepo;
    private final EmailService emailService;
    private final TokenService tokenService;

    public AuthService(UserRepository userRepo,
                       RoleRepository roleRepo,
                       PasswordEncoder encoder,
                       AuthenticationManager authManager,
                       JwtService jwt,
                       PasswordResetTokenRepository resetRepo,
                       EmailService emailService, TokenService tokenService) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.encoder = encoder;
        this.authManager = authManager;
        this.jwt = jwt;
        this.resetRepo = resetRepo;
        this.emailService = emailService;
        this.tokenService = tokenService;
    }



    @Transactional
    public void register(RegisterRequest dto) {
        // Verifica se email ou username já existem
        if (userRepo.existsByEmail(dto.getEmail())) {
            throw new IllegalArgumentException("E-mail já cadastrado");
        }
        if (userRepo.existsByUsername(dto.getUsername())) {
            throw new IllegalArgumentException("Username já cadastrado");
        }

        UserEntity user = new UserEntity();
        user.setEmail(dto.getEmail());
        user.setUsername(dto.getUsername());
        user.setName(dto.getName());
        user.setPassword(encoder.encode(dto.getPassword()));
        user.setDateBirth(dto.getDateBirth());
        user.setNumberTel(dto.getNumberTel());
        user.setEnabled(true);

        // Verifica se é o primeiro usuário
        if (userRepo.count() == 0) {
            // Primeiro usuário → ADMIN
            RoleEntity adminRole = roleRepo.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new IllegalStateException("Role ROLE_ADMIN não encontrada"));
            user.setRoles(Set.of(adminRole));
        } else {
            // Usuário normal → USER
            RoleEntity userRole = roleRepo.findByName("ROLE_USER")
                    .orElseThrow(() -> new IllegalStateException("Role ROLE_USER não encontrada"));
            user.setRoles(Set.of(userRole));
        }

        userRepo.save(user);
    }

    public TokenResponse login(LoginRequest dto) {
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword());
        authManager.authenticate(auth);

        UserEntity user = userRepo.findByUsername(dto.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", user.getRoles().stream().map(RoleEntity::getName).toList());

        String access = jwt.generateAccess(user.getUsername(), claims);
        String refresh = jwt.generateRefresh(user.getUsername());

        // 🔹 salva token único (sessão única)
        tokenService.saveUserToken(user.getId(), access);

        return new TokenResponse(access, refresh);
    }


    public TokenResponse refresh(String refreshToken) {
        String subject = jwt.getSubject(refreshToken);
        UserEntity user = userRepo.findByUsername(subject)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", user.getRoles().stream().map(RoleEntity::getName).toList());

        // CORRIGIDO: usar username, não name
        String access = jwt.generateAccess(user.getUsername(), claims);
        return new TokenResponse(access, refreshToken);
    }


    @Transactional
    public void forgotPassword(ForgotPasswordRequest req, String appBaseUrl) {
        UserEntity user = userRepo.findByEmail(req.getEmail()).orElse(null);
        if (user == null) return; // não revelar existência

        String token = UUID.randomUUID().toString();
        PasswordResetToken entity = new PasswordResetToken();
        entity.setToken(token);
        entity.setUser(user);
        entity.setExpiresAt(Instant.now().plusSeconds(60 * 30)); // 30min
        entity.setUsed(false);
        resetRepo.save(entity);

        String link = appBaseUrl + "/reset-password?token=" + token;
        emailService.send(user.getEmail(), "Recuperação de senha",
                "Olá, " + (user.getName() != null ? user.getName() : "usuário") +
                        ". Use este link para redefinir sua senha (30 min): " + link);
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest req) {
        PasswordResetToken token = resetRepo.findByToken(req.getToken())
                .orElseThrow(() -> new IllegalArgumentException("Token inválido"));

        if (token.isUsed() || token.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Token expirado/indisponível");
        }

        UserEntity user = token.getUser();
        user.setPassword(encoder.encode(req.getNewPassword()));
        token.setUsed(true);
    }
}
