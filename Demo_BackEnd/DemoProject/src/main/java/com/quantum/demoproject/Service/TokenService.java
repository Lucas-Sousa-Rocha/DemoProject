package com.quantum.demoproject.Service;

import com.quantum.demoproject.model.UserTokenEntity;
import com.quantum.demoproject.repository.UserTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class TokenService {

    private final UserTokenRepository repo;

    public TokenService(UserTokenRepository repo) {
        this.repo = repo;
    }

    @Transactional
    public void saveUserToken(Long userId, String token) {
        UserTokenEntity userToken = new UserTokenEntity(userId, token);
        repo.save(userToken); // substitui se já existir (mesmo userId)
    }

    public boolean isTokenValid(Long userId, String token) {
        Optional<UserTokenEntity> stored = repo.findById(userId);
        return stored.map(t -> t.getToken().equals(token)).orElse(false);
    }

    @Transactional
    public void deleteUserToken(Long userId) {
        repo.deleteByUserId(userId);
    }
}
