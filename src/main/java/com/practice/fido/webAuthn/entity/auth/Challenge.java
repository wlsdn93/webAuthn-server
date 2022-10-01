package com.practice.fido.webAuthn.entity.auth;

import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.time.LocalDateTime;

@Entity
@NoArgsConstructor
public class Challenge {
    @Id
    @Column(name = "challenge")
    private String challenge;

    @Column(name = "timeout")
    private final LocalDateTime timeout = LocalDateTime.now().plusMinutes(1);

    public Challenge(String challenge) {
        this.challenge = challenge;
    }

}
