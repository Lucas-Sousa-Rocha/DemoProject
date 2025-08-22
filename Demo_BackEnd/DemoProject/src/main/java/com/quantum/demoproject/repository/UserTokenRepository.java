package com.quantum.demoproject.repository;

import com.quantum.demoproject.model.UserTokenEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserTokenRepository extends JpaRepository<UserTokenEntity, Long> {
    @Transactional
    void deleteByUserId(Long userId);
}

