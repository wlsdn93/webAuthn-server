package com.practice.fido.webAuthn.entity.domain;

import javax.persistence.*;

@Entity
public class EcPublicKeySource {

    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "PUBLIC_KEY_ID")
    private String publicKeyId;

    @Column(name = "USER_ID")
    private String userId;

    @Column(name = "KEY_TYPE")
    private String keyType;

    @Column(name = "ALGORITHM")
    private String algorithm;

    @Column(name = "CURVE_TYPE")
    private String curveType;

    @Column(name = "X_COORDINATE")
    private String xCoordinate;

    @Column(name = "Y_COORDINATE")
    private String yCoordinate;



}
