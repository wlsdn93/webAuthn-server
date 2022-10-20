package com.practice.fido.webAuthn.repository;

import com.practice.fido.webAuthn.entity.domain.PublicKeySource;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PublicKeySourceRepository extends JpaRepository<PublicKeySource, String> {
}
