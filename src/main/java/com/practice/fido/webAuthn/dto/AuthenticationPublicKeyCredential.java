package com.practice.fido.webAuthn.dto;

import lombok.Getter;

@Getter
public class AuthenticationPublicKeyCredential {
    private String id;
    private String authenticatorData;
    private String clientDataJSON;
    private String signature;
    private String userHandle;
    private String type;
}
