package com.practice.fido.webAuthn.repository;

import com.practice.fido.webAuthn.entity.domain.EcPublicKeySource;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EcPubKeySourceRepository extends JpaRepository<EcPublicKeySource, String> {
}
