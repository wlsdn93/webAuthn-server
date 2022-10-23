package com.practice.fido.webAuthn.dto.registration;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.Base64;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientData implements Serializable {
    public String origin;
    public String challenge;
    public Boolean crossOrigin;
    public String type;

    public String getChallenge() {
        return new String(Base64.getDecoder().decode(challenge));
    }
}
