package com.practice.fido.webAuthn.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.practice.fido.webAuthn.entity.domain.EcPublicKeySource;
import com.practice.fido.webAuthn.repository.EcPubKeySourceRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class WebAuthnServiceTest {

    @Autowired
    EcPubKeySourceRepository keySourceRepository;
    static Base64.Decoder decoder = Base64.getDecoder();
    @Test
    @DisplayName("JSON 파싱 확인하기")
    public void parseAttestationObject() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        final String base64Signature = "MEUCIQDL4GqDMhphN0clc7lVV87KG0CpstF/uEakF8n1Shln1QIgbMwnGqhbW1YDxofp4UrhPU3x+WX2Sc6XnGaUu6qb3hI=";
        final String base64AuthData = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMALQr6E/bsTVnj2wDNeBSjfaQsfNF93xqo6nkZoel1CW5ZjxdzAoOiL9UTgxfdPaUBAgMmIAEhWCDH7Ugz3uf/f5ghXaaVDIM/s9eARc/E86/ukagnsSoqSCJYIBGMhZ/Z0v1BrG6S9opII2DW5hWOkWo7Aw8xaLjNenyT";
        byte[] signatureFromClient = decoder.decode(base64Signature);
        byte[] AuthenticatorData = decoder.decode(base64AuthData);

        byte[] idLenBytes = Arrays.copyOfRange(AuthenticatorData, 53, 55);
        int idLen = Integer.parseInt(new BigInteger(idLenBytes).toString(16), 16);
        byte[] pubKeyCBOR = Arrays.copyOfRange(AuthenticatorData, 55 + idLen, AuthenticatorData.length);

        // get publicKey from Authenticator Data
        EcPublicKeyObject ecPublicKeyObject = parseEncodedPublicKey(pubKeyCBOR);
        EcPublicKeySource keySource = getKeySource(ecPublicKeyObject, "testId");

        // generate clientDataHash
        String base64ClientDataJSON = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZUZkUlozQnRSMkpoVHpSb2JrRklVbFZtTm1aZlJHRmZia2xWIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==";
        byte[] clientDataHash = hash("SHA-256", base64ClientDataJSON);

        // make a message to verify the signature with alg
        byte[] message = getMessage(AuthenticatorData, clientDataHash);

        // verify the signature
        // SHA256withRSA
        PublicKey pubKey = getEcPublicKey(keySource);
        Signature signature = getECDSA(ecPublicKeyObject);
        signature.initVerify(pubKey);
        signature.update(message);
        boolean verified = signature.verify(signatureFromClient);
        System.out.println("verify = " + verified);
        if(verified) {
            System.out.println("SAVE KEYSOURCE");
//            keySourceRepository.save(keySource);
            // return jwt or something
        } else {
            System.err.println("THROW EXCEPTION");
            // throw exception
        }
    }

    private PublicKey getEcPublicKey(EcPublicKeySource keySource) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance(keySource.getAlgorithm());
        ECGenParameterSpec parameterSpec = new ECGenParameterSpec(keySource.getStandardName());
        parameters.init(parameterSpec);

        BigInteger x = new BigInteger(keySource.getXCoordinate(), 16);
        BigInteger y = new BigInteger(keySource.getYCoordinate(), 16);
        ECPoint ecPoint = new ECPoint(x, y);

        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance(keySource.getAlgorithm());
        return keyFactory.generatePublic(publicKeySpec);
    }

    // algorithm, standard_name, x, y
    // x, y 는 x.toString(16) 해서  DB 에 저장..
    // 다시 꺼내오면 .. new BigInteger(hexString, 16) 하면 됨
    //
    private static EcPublicKeySource getKeySource(EcPublicKeyObject publicKeyJson, String userId) throws IOException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        String standardName = getStandardNameOfCurveType(publicKeyJson);
        byte[] minus2 = decoder.decode(publicKeyJson.xCoordinate);
        byte[] minus3 = decoder.decode(publicKeyJson.yCoordinate);

        String x = new BigInteger(1, minus2).toString(16);
        String y = new BigInteger(1, minus3).toString(16);

        // standardName는 cvr 에서 가져와야함... cvr enum 필요..
        return EcPublicKeySource.builder()
                .userId(userId)
                .xCoordinate(x)
                .yCoordinate(y)
                .standardName(standardName)
                .build();
    }

    private static EcPublicKeyObject parseEncodedPublicKey(byte[] pubKeyCBOR) throws IOException {
        EcPublicKeyObject ecPublicKeyObject = new ObjectMapper().readValue(stringifyCBOR(pubKeyCBOR), new TypeReference<>() {});
        return ecPublicKeyObject;
    }

    /**
     * NIST P-256 also known as secp256r1
     * NIST P-384 also known as secp384r1
     * NIST P-521 also known as secp521r1
     * reference from RFC8152 SECTION 13.1
     */
    private static String getStandardNameOfCurveType(EcPublicKeyObject ecPublicKeyObject) {
        switch (ecPublicKeyObject.curveType) {
            case "1" : return "secp256r1";
            case "2" : return "secp384r1";
            case "3" : return "secp521r1";
        }
        throw new IllegalArgumentException("not supported curve type");
    }

    /**
     * ES256 : ECDSA w/ SHA-256
     * ES384 : ECDSA w/ SHA-384
     * ES512 : ECDSA w/ SHA-512
     * reference from
     * 1. RFC8152 SECTION 8.1
     * 2. https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunEC
     */
    private static Signature getECDSA(EcPublicKeyObject ecPublicKeyObject) throws NoSuchAlgorithmException, NoSuchProviderException {
        switch (ecPublicKeyObject.alg) {
            case "-7" : return Signature.getInstance("SHA256withECDSA", "SunEC");
            case "-35" : return Signature.getInstance("SHA384withECDSA", "SunEC");
            case "-36" : return Signature.getInstance("SHA512withECDSA", "SunEC");
        }
        throw new IllegalArgumentException("not supported alg");
    }

    private static String getKeyType(EcPublicKeyObject ecPublicKeyObject) {
        switch (ecPublicKeyObject.keyType) {
            case "2" : return "EC";
            case "3" : return "RSA";
        }
        throw new IllegalArgumentException("not supported key type");
    }

    private static byte[] getMessage(byte[] decodedAuthData, byte[] clientDataHash) {
        return ByteBuffer.allocate(decodedAuthData.length + clientDataHash.length)
                .put(decodedAuthData)
                .put(clientDataHash)
                .array();
    }
    private static byte[] hash(String alg, String clientDataJson) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(alg);
        md.update(decoder.decode(clientDataJson));
        return md.digest();
    }

    private static String stringifyCBOR(byte[] cbor) throws IOException {
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

    static class EcPublicKeyObject {
        @JsonProperty("1")
        String keyType;
        @JsonProperty("3")
        String alg;
        @JsonProperty("-1")
        String curveType;
        @JsonProperty("-2")
        String xCoordinate;
        @JsonProperty("-3")
        String yCoordinate;
    }

}
