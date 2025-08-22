package com.quantum.demoproject.Controller;

import com.quantum.demoproject.DTO.*;
import com.quantum.demoproject.Service.TokenService;
import com.quantum.demoproject.auth.AuthService;
import com.quantum.demoproject.model.RoleEntity;
import com.quantum.demoproject.model.UserEntity;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

    public AuthController(AuthService authService, TokenService tokenService) {
        this.authService = authService;
        this.tokenService = tokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest dto) {
        authService.register(dto);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest dto) {
        try {
            TokenResponse token = authService.login(dto); // salva token único no AuthService
            return ResponseEntity.ok(token);
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Usuário ou senha inválidos"));
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
        String appBase = (baseUrl != null && !baseUrl.isBlank()) ? baseUrl : "http://localhost:8080";
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
    public ResponseEntity<MeView> me(@AuthenticationPrincipal UserEntity user) {
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        MeView meView = new MeView(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getName(),
                user.getRoles().stream()
                        .map(RoleEntity::getName)
                        .toList()
        );
        return ResponseEntity.ok(meView);
    }

    @GetMapping("/admin/ping")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String adminPing() { return "admin ok"; }

@PostMapping("/logout")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<?> logout(@AuthenticationPrincipal UserEntity user) {
        tokenService.deleteUserToken(user.getId()); // agora realmente exclui
    return ResponseEntity.ok(Map.of("message", "Logout realizado. Token removido."));
}

}
