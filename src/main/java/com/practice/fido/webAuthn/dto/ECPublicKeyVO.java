package com.practice.fido.webAuthn.dto;

import com.practice.fido.webAuthn.entity.domain.PublicKeySource;
import lombok.Getter;

import java.math.BigInteger;
import java.util.Base64;

import static java.util.Base64.*;

@Getter
public class ECPublicKeyVO {

    private final Decoder decoder = Base64.getDecoder();
    private String keyType;
    private String alg;
    private String curveType;
    private BigInteger xCoordinate;
    private BigInteger yCoordinate;

    public ECPublicKeyVO(PublicKeySource keySource) {
        this.keyType = keySource.getOne();
        this.alg = keySource.getThree();
        this.curveType = keySource.getMinusOne();
        this.xCoordinate = new BigInteger(1, decoder.decode(keySource.getMinusTwo()));
        this.yCoordinate = new BigInteger(1, decoder.decode(keySource.getMinusThree()));
    }

    public String getStandardNameOfCurveType() {
        if(curveType.equals("1")) {
            return "secp256r1";
        }
        throw new IllegalArgumentException("not supported curve type");
    }

}
