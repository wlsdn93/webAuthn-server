package com.practice.fido.webAuthn.dto.registration;

import lombok.Getter;

@Getter
public class PubKeyCredParams {
    private Integer alg;
    private String type;

    public PubKeyCredParams(Integer alg, String type) {
        this.alg = alg;
        this.type = type;
    }
}
