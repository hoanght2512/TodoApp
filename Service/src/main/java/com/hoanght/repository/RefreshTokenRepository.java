package com.hoanght.repository;

import com.hoanght.entity.RefreshToken;
import jakarta.transaction.Transactional;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    void deleteByToken(String token);

    @Transactional
    void deleteByUsername(String username);

    @Transactional
    void deleteByExpiryDateBefore(Long expiryDate);
}