package com.quantum.demoproject.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_tokens")
public class UserTokenEntity {

    @Id
    @Column(name = "user_id", unique = true)
    private Long userId; // mesmo ID da tabela de usuários

    @Column(nullable = false, length = 500)
    private String token;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    public UserTokenEntity() {}

    public UserTokenEntity(Long userId, String token) {
        this.userId = userId;
        this.token = token;
        this.createdAt = LocalDateTime.now();
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
