package com.practice.fido.webAuthn.dto;

import lombok.Getter;

@Getter
public class RegistrationPublicKeyCredential {

    private String authenticatorAttachment;
    private String id;
    private String attestationObject;
    private String clientDataJSON;
    private String type;

}
