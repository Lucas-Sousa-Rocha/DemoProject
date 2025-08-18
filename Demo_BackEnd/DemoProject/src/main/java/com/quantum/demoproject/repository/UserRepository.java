package com.quantum.demoproject.repository;

import com.quantum.demoproject.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    // Buscar usuário pelo username (para login)
    Optional<UserEntity> findByUsername(String username);

    // Buscar usuário pelo email
    Optional<UserEntity> findByEmail(String email);

    // Verificar existência de username (para cadastro)
    boolean existsByUsername(String username);

    // Verificar existência de email (para cadastro)
    boolean existsByEmail(String email);
}
