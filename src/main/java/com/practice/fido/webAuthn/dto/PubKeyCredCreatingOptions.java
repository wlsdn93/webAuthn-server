package com.practice.fido.webAuthn.dto;

import com.practice.fido.webAuthn.entity.auth.AuthenticatorSelection;
import com.practice.fido.webAuthn.entity.auth.PubKeyCredParams;
import com.practice.fido.webAuthn.entity.auth.RelyingParty;
import com.practice.fido.webAuthn.entity.auth.UserInfo;
import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
public class PubKeyCredCreatingOptions {

    /**
     * challenge
     * rp
     * user
     * pubKeyCredParams
     * timeout
     * attestation
     */
    private String challenge;
    private RelyingParty rp;
    private UserInfo user;
    private List<PubKeyCredParams> pubKeyCredParams;
    private AuthenticatorSelection authenticatorSelection;
    private final Integer timeout = 60000;
    private final String attestation = "direct";

    @Builder
    public PubKeyCredCreatingOptions(String challenge,
                                     RelyingParty relyingParty,
                                     UserInfo user,
                                     List<PubKeyCredParams> pubKeyCredParams,
                                     AuthenticatorSelection authenticatorSelection) {
        this.challenge = challenge;
        this.rp = relyingParty;
        this.user = user;
        this.pubKeyCredParams = pubKeyCredParams;
        this.authenticatorSelection = authenticatorSelection;
    }
}
