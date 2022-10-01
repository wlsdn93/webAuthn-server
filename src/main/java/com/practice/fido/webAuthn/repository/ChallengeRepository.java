package com.practice.fido.webAuthn.repository;

import com.practice.fido.webAuthn.entity.auth.Challenge;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ChallengeRepository extends JpaRepository<Challenge, String> {
}
