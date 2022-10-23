package com.practice.fido.webAuthn.dto.authentication;

import lombok.Getter;

import java.util.List;
import java.util.stream.Collectors;

@Getter
public class AllowCredential {
    private final String type = "public-key";
    // credentialId
    private String Id;
    private List<String> transports;

    public AllowCredential(String id, List<AuthenticatorTransport> transports) {
        Id = id;
        this.transports = transports
                .stream()
                .map(item -> item.value)
                .collect(Collectors.toList());
    }

    public enum AuthenticatorTransport {
        USB("usb"),
        NFC("nfc"),
        BLE("ble"),
        HYBRID("hybrid"),
        INTERNAL("internal");

        private String value;

        AuthenticatorTransport(String value) {
            this.value = value;
        }
    }
}
