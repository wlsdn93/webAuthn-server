package com.practice.fido.webAuthn.repository;

import com.practice.fido.webAuthn.entity.PublicKeySource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface PublicKeySourceRepository extends JpaRepository<PublicKeySource, String> {

    @Query(nativeQuery = true,
    value = "select * from public_key_source where user_id = :userId")
    Optional<PublicKeySource> findByUserId(@Param("userId") String userId);
}
