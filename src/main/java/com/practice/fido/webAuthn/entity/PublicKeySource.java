package com.practice.fido.webAuthn.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;


@Entity
@Getter
@Table(name = "PUBLIC_KEY_SOURCE")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PublicKeySource {

    @Id
    @Column(name = "CREDENTIAL_ID")
    @JsonIgnore
    private String credentialId;
    @Column(name = "USER_ID")
    @JsonIgnore
    private String userId;

    @JsonProperty("1")
    @Column(name = "ONE")
    private String one;

    @JsonProperty("3")
    @Column(name = "THREE")
    private String three;

    @JsonProperty("-1")
    @Column(name = "MINUS_ONE")
    private String minusOne;

    @JsonProperty("-2")
    @Column(name = "MINUS_TWO")
    private String minusTwo;

    @JsonProperty("-3")
    @Column(name = "MINUS_THREE")
    private String minusThree;

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getKeyType() {
        switch (one) {
            case "2" : return "EC";
            case "3" : return "RSA";
        }
        throw new RuntimeException("지원하지 않는 키타입");
    }
}
