package com.practice.fido.webAuthn.dto.registration;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
public class PubKeyCredCreatingOptions {
    private final String challenge;
    private final RelyingParty rp;
    private final UserInfo user;
    private final List<PubKeyCredParams> pubKeyCredParams;
    private final AuthenticatorSelection authenticatorSelection;
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
