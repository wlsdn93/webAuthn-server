package com.practice.fido.webAuthn.entity.auth;

import lombok.Getter;

@Getter
public class AuthenticatorSelection {
    private String attachment;
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

    public AuthenticatorSelection(AuthenticatorAttachment attachment,
                                  UserVerification userVerification,
                                  ResidentKey residentKey,
                                  Boolean requireResidentKey) {
        this.attachment = attachment.value;
        this.userVerification = userVerification.value;
        this.residentKey = residentKey.value;
        this.requireResidentKey = requireResidentKey;
    }
}
