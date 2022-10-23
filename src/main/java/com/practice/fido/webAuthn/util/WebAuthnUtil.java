package com.practice.fido.webAuthn.util;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.practice.fido.webAuthn.dto.registration.Attestation;
import com.practice.fido.webAuthn.dto.common.Challenge;
import com.practice.fido.webAuthn.dto.registration.ClientData;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class WebAuthnUtil {
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private static final Base64.Decoder urlDecoder = Base64.getUrlDecoder();
    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final SecureRandom random = new SecureRandom();
    private static final ObjectMapper objMapper = new ObjectMapper();

    public static Challenge generateChallenge() {
        byte[] buffer = new byte[20];
        random.nextBytes(buffer);
        return new Challenge(encoder.encodeToString(buffer));
    }

    public static byte[] decodeBase64(String base64) {
        return decoder.decode(base64);
    }

    public static byte[] hash(String clientDataJson) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(decoder.decode(clientDataJson));
        return md.digest();
    }

    public static String stringifyCBOR(byte[] cbor) throws IOException {
        CBORFactory cborFactory = new CBORFactory();
        CBORParser parser = cborFactory.createParser(cbor);

        JsonFactory jsonFactory = new JsonFactory();
        StringWriter stringWriter = new StringWriter();
        JsonGenerator jsonGenerator = jsonFactory.createGenerator(stringWriter);
        while(parser.nextToken() != null) {
            jsonGenerator.copyCurrentEvent(parser);
        }
        jsonGenerator.flush();
        return stringWriter.toString();
    }

    public static Attestation parseAttestation(String base64EncodedCborAttestation) throws IOException {
        byte[] attestationObject = decoder.decode(base64EncodedCborAttestation);
        return objMapper.readValue(stringifyCBOR(attestationObject), new TypeReference<>() {
        });
    }

    public static ClientData parseClientData(String clientDataJSON) throws JsonProcessingException {
        String decodedClientData = new String(decoder.decode(clientDataJSON), StandardCharsets.UTF_8);
        return objMapper.readValue(decodedClientData, new TypeReference<>() {
        });
    }

}
