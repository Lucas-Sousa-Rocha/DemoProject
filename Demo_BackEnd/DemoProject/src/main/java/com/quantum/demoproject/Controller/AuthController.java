package com.quantum.demoproject.Controller;

import com.quantum.demoproject.DTO.*;
import com.quantum.demoproject.auth.AuthService;
import com.quantum.demoproject.model.RoleEntity;
import com.quantum.demoproject.model.UserEntity;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest dto) {
        authService.register(dto);
        return ResponseEntity.ok().build();
    }

//    @PostMapping("/login")
//    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest dto) {
//        return ResponseEntity.ok(authService.login(dto));
//    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest dto) {
        try {
            TokenResponse token = authService.login(dto);
            return ResponseEntity.ok(token);
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Usuário ou senha inválidos"));
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Usuário não encontrado"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Erro ao processar login"));
        }
    }


    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestParam String refreshToken) {
        return ResponseEntity.ok(authService.refresh(refreshToken));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgot(@Valid @RequestBody ForgotPasswordRequest dto,
                                       @RequestHeader(value="X-App-Base-Url", required=false) String baseUrl) {
        String appBase = (baseUrl != null && !baseUrl.isBlank()) ? baseUrl : "http://localhost:3000";
        authService.forgotPassword(dto, appBase);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> reset(@Valid @RequestBody ResetPasswordRequest dto) {
        authService.resetPassword(dto);
        return ResponseEntity.ok().build();
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/me")
    public MeView me(@AuthenticationPrincipal UserEntity user) {
        return new MeView(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getName(),
                user.getRoles()
        );
    }




    @GetMapping("/admin/ping")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String adminPing() { return "admin ok"; }

    public static class MeView {
        private Long id;
        private String email;
        private String username;
        private String name;
        private Set<RoleEntity> roles;

        public MeView(Long id, String email, String username, String name, Set<RoleEntity> roles) {
            this.id = id;
            this.email = email;
            this.username = username;
            this.name = name;
            this.roles = roles;
        }

        public Long getId() { return id; }
        public String getEmail() { return email; }
        public String getUsername() { return username; }
        public String getName() { return name; }
        public Set<RoleEntity> getRoles() { return roles; }
    }
}
