package com.practice.fido.webAuthn.entity.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Attestation  implements Serializable  {
    public String fmt;
    public AttestationStatement attStmt;
    public String authData;
    public class AttestationStatement  implements Serializable {
        Integer alg;
        String sig;

        public Integer getAlg() {
            return alg;
        }

        public String getSig() {
            return sig;
        }
    }
}
