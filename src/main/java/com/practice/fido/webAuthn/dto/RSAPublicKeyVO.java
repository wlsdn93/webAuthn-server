package com.practice.fido.webAuthn.dto;

import com.practice.fido.webAuthn.entity.domain.PublicKeySource;
import lombok.Getter;

import java.math.BigInteger;
import java.util.Base64;

@Getter
public class RSAPublicKeyVO {

    private final Base64.Decoder decoder = Base64.getDecoder();
    private String keyType;
    private String alg;
    private BigInteger modulus;
    private BigInteger exponent;
    public RSAPublicKeyVO(PublicKeySource keySource) {
        this.keyType = keySource.getOne();
        this.alg = keySource.getThree();
        this.modulus = new BigInteger(1, decoder.decode(keySource.getMinusOne()));
        this.exponent = new BigInteger(1, decoder.decode(keySource.getMinusTwo()));
    }


}
