package com.practice.fido.webAuthn.dto.authentication;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
public class PublicKeyCredRequestOptions {

    private final String challenge;
    private final String userVerification;
    private final List<AllowCredential> allowCredentials;
    private final Integer timeout = 60000;
    private final String rpId;

    @Builder
    public PublicKeyCredRequestOptions(String challenge, String userVerification, List<AllowCredential> allowCredentials, String rpId) {
        this.challenge = challenge;
        this.userVerification = userVerification;
        this.allowCredentials = allowCredentials;
        this.rpId = rpId;
    }
}
