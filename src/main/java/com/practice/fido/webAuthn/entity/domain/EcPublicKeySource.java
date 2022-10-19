package com.practice.fido.webAuthn.entity.domain;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Getter
@Table(name = "EC_PUBKEY")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class EcPublicKeySource {

    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "KEY_ID")
    private String publicKeyId;

    @Column(name = "USER_ID")
    private String userId;

    @Column(name = "ALGORITHM")
    private final String algorithm = "EC";

    @Column(name = "STANDARD_NAME")
    private String standardName;

    @Column(name = "X")
    private String xCoordinate;

    @Column(name = "Y")
    private String yCoordinate;

    @Builder
    public EcPublicKeySource(String userId, String standardName, String xCoordinate, String yCoordinate) {
        this.userId = userId;
        this.standardName = standardName;
        this.xCoordinate = xCoordinate;
        this.yCoordinate = yCoordinate;
    }

}
