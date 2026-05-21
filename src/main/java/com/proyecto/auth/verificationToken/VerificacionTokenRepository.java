package com.proyecto.auth.verificationToken;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface  VerificacionTokenRepository extends JpaRepository<VerificacionToken, Long>{
    Optional<VerificacionToken> findByToken(String token);
}
