package com.practice.fido.webAuthn.entity.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientData implements Serializable {
    public String origin;
    public String challenge;
    public Boolean crossOrigin;
    public String type;
}
