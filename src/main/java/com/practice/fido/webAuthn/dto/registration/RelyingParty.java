package com.practice.fido.webAuthn.dto.registration;

import lombok.Getter;

@Getter
public class RelyingParty {
    private String name;
    private String id;

    public RelyingParty(String rpName, String id) {
        this.name = rpName;
        this.id = id;
    }
}
