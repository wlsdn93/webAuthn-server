package com.practice.fido.webAuthn.dto.registration;

import lombok.Getter;

@Getter
public class AuthenticatorSelection {
    private String authenticatorAttachment;
    private String userVerification;
    private String residentKey;
    private Boolean requireResidentKey;
    public enum AuthenticatorAttachment {
        CROSS_PLATFORM("cross-platform"),
        PLATFORM("platform");
        private final String value;
        AuthenticatorAttachment(String value) {
            this.value = value;
        }
    }
    public enum ResidentKey {
        REQUIRED("required"),
        PREFERRED("preferred"),
        DISCOURAGED("discouraged");
        private final String value;
        ResidentKey(String value) {
            this.value = value;
        }
    }
    public enum UserVerification {
        REQUIRED("required"),
        PREFERRED("preferred"),
        DISCOURAGED("discouraged");
        private final String value;
        UserVerification(String value) {
            this.value = value;
        }
    }

    public AuthenticatorSelection(AuthenticatorAttachment authenticatorAttachment,
                                  UserVerification userVerification,
                                  ResidentKey residentKey,
                                  Boolean requireResidentKey) {
        this.authenticatorAttachment = authenticatorAttachment.value;
        this.userVerification = userVerification.value;
        this.residentKey = residentKey.value;
        this.requireResidentKey = requireResidentKey;
    }
}
