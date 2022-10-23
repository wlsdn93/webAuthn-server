package com.practice.fido.webAuthn.dto.registration;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Attestation implements Serializable  {
    public String fmt;
    public AttestationStatement attStmt;
    public String authData;
    public static class AttestationStatement implements Serializable {
        String alg;
        String sig;

        String x5c;
        public String getAlg() {
            return alg;
        }
        public String getSig() {
            return sig;
        }
        public String getX5c() { return x5c == null ? "" : x5c; }
    }
}
