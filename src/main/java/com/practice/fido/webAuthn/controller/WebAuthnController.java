package com.practice.fido.webAuthn.controller;


import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.JSONPObject;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.practice.fido.webAuthn.dto.PubKeyCredCreatingOptions;
import com.practice.fido.webAuthn.dto.PublicKeyCredential;
import com.practice.fido.webAuthn.service.WebAuthnService;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class WebAuthnController {

    private final WebAuthnService authService;

    public WebAuthnController(WebAuthnService authService) {
        this.authService = authService;
    }

    @GetMapping("/credential/options")
    public PubKeyCredCreatingOptions createCredentialOptions() {
        return authService.getCredentialOptions();
    }

    @PostMapping("/credential/attestation")
    public boolean attestCredential(@RequestBody PublicKeyCredential credential) throws IOException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, SignatureException, NoSuchProviderException, InvalidKeyException {
        return this.authService.attestPublicKeyCredential(credential);
    }


}
