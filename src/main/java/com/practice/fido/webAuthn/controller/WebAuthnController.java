package com.practice.fido.webAuthn.controller;


import com.practice.fido.webAuthn.dto.AuthenticationPublicKeyCredential;
import com.practice.fido.webAuthn.dto.registration.PubKeyCredCreatingOptions;
import com.practice.fido.webAuthn.dto.authentication.PublicKeyCredRequestOptions;
import com.practice.fido.webAuthn.dto.RegistrationPublicKeyCredential;
import com.practice.fido.webAuthn.service.WebAuthnService;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

@RestController
@RequestMapping("/api/auth")
public class WebAuthnController {

    private final WebAuthnService authService;

    public WebAuthnController(WebAuthnService authService) {
        this.authService = authService;
    }

    @GetMapping("/credential/creating/options")
    public PubKeyCredCreatingOptions createCredentialOptions() {
        return authService.getCredentialCreatingOptions();
    }

    @GetMapping("/credential/request/options")
    public PublicKeyCredRequestOptions requestCredentialOptions() {
        return authService.getCredentialRequestOptions();
    }

    @PostMapping("/credential/attestation")
    public boolean attestCredential(@RequestBody RegistrationPublicKeyCredential credential) throws IOException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, SignatureException, NoSuchProviderException, InvalidKeyException {
        return this.authService.attestPublicKeyCredential(credential);
    }

    @PostMapping("/credential/assertion")
    public boolean assertCredential(@RequestBody AuthenticationPublicKeyCredential credential) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, SignatureException, NoSuchProviderException, InvalidKeyException {
        return this.authService.assertPublicKeyCredential(credential);
    }


}
