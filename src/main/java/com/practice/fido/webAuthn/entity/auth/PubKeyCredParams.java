package com.practice.fido.webAuthn.entity.auth;

import lombok.Getter;

@Getter
public class PubKeyCredParams {
//    ES256(-7, "public-key"),
//    RS256(-257, "public-key");
    private Integer alg;
    private String type;

    public PubKeyCredParams(Integer alg, String type) {
        this.alg = alg;
        this.type = type;
    }
}
