package com.practice.fido.webAuthn.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.practice.fido.webAuthn.dto.PubKeyCredCreatingOptions;
import com.practice.fido.webAuthn.dto.PublicKeyCredential;
import com.practice.fido.webAuthn.entity.auth.*;
import com.practice.fido.webAuthn.repository.ChallengeRepository;
import com.practice.fido.webAuthn.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
@Slf4j
@Transactional
public class WebAuthnService {

    /**
     * challenge
     * rp
     * user
     * pubKeyCredParams
     * timeout
     * attestation
     */
    private static final SecureRandom random = new SecureRandom();
    private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private static final ObjectMapper objMapper = new ObjectMapper();
    private final ChallengeRepository challengeRepository;

    private final UserRepository userRepository;

    public WebAuthnService(ChallengeRepository challengeRepository, UserRepository userRepository) {
        this.challengeRepository = challengeRepository;
        this.userRepository = userRepository;
    }

    public PubKeyCredCreatingOptions startRegistration() {
        return null;
    }

    public String getChallenge() {
        byte[] buffer = new byte[20];
        random.nextBytes(buffer);
        String challenge = encoder.encodeToString(buffer);
        return challenge;
    }

    public PubKeyCredCreatingOptions getCredentialOptions() {
        //challenge
        String challenge = getChallenge();

        //rp
        String rpName = "x8byte security";
        String rpId = "localhost";
        RelyingParty rp = new RelyingParty(rpName, rpId);

        // user
//        User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("존해하지 않는 사용자"));
//        String name = user.getUsername();
//        String displayName = user.getDisplayName();
        String userId = "1";
        String name = "jinwoo";
        String displayName = "hello";
        UserInfo userInfo = new UserInfo(userId, name, displayName);

        //pubKeyCredParams
        List<PubKeyCredParams> pubKeyCredParams = new ArrayList<>();
        pubKeyCredParams.add(new PubKeyCredParams(-7, "public-key"));
        pubKeyCredParams.add(new PubKeyCredParams(-257, "public-key"));

        //authenticationSelection
        AuthenticatorSelection authenticatorSelection =
                new AuthenticatorSelection(AuthenticatorSelection.AuthenticatorAttachment.PLATFORM,
                                            AuthenticatorSelection.UserVerification.PREFERRED,
                                            AuthenticatorSelection.ResidentKey.PREFERRED,
                            true);

        return PubKeyCredCreatingOptions.builder()
                .challenge(challenge)
                .relyingParty(rp)
                .user(userInfo)
                .pubKeyCredParams(pubKeyCredParams)
                .authenticatorSelection(authenticatorSelection)
                .build();
    }
    public boolean attestPublicKeyCredential(PublicKeyCredential credential) throws IOException {
        log.info("authenticatorAttachment : {}", credential.getAuthenticatorAttachment());
        log.info("id : {}", credential.getId());
        log.info("type : {}", credential.getType());
        ClientData clientData = parseClientData(credential.getClientDataJSON());
        Attestation attestation = parseAttestation(credential.getAttestationObject());
        log.info("challenge : {}", clientData.challenge);
        log.info("origin : {}", clientData.origin);
        log.info("crossOrigin : {}", clientData.crossOrigin);
        log.info("credential type : {}", clientData.type);
        log.info("signature : {}", attestation.attStmt.getSig());
        log.info("algorithm : {}", attestation.attStmt.getAlg());
        log.info("fmt : {}", attestation.fmt);
        log.info("authData : {}", attestation.authData);
        return true;
    }

    private ClientData parseClientData(String clientDataJSON) throws JsonProcessingException {
        String decodedClientData = new String(decoder.decode(clientDataJSON), StandardCharsets.UTF_8);
        return objMapper.readValue(decodedClientData, new TypeReference<>() {
        });
    }

    private Attestation parseAttestation(String base64EncodedCborAttestation) throws IOException {
        return objMapper.readValue(stringifyCBOR(base64EncodedCborAttestation), new TypeReference<>() {
        });
    }

    private static String stringifyCBOR(String base64EncodedCBOR) throws IOException {
        byte[] decodedCBOR = decoder.decode(base64EncodedCBOR);
        CBORFactory cborFactory = new CBORFactory();
        CBORParser parser = cborFactory.createParser(decodedCBOR);

        JsonFactory jsonFactory = new JsonFactory();
        StringWriter stringWriter = new StringWriter();
        JsonGenerator jsonGenerator = jsonFactory.createGenerator(stringWriter);
        while(parser.nextToken() != null) {
            jsonGenerator.copyCurrentEvent(parser);
        }
        jsonGenerator.flush();
        
        return stringWriter.toString();
    }

}
