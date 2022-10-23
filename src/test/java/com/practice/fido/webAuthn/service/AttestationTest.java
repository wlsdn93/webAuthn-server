package com.practice.fido.webAuthn.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import com.practice.fido.webAuthn.dto.registration.ClientData;
import com.practice.fido.webAuthn.entity.PublicKeySource;
import com.practice.fido.webAuthn.repository.PublicKeySourceRepository;
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

public class AttestationTest {

    @Autowired
    PublicKeySourceRepository keySourceRepository;
    static Base64.Decoder decoder = Base64.getDecoder();
    @Test
    @DisplayName("WebAuthn Test")
    public void parseAttestationObject() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        final String base64Signature = "MEUCIQDL4GqDMhphN0clc7lVV87KG0CpstF/uEakF8n1Shln1QIgbMwnGqhbW1YDxofp4UrhPU3x+WX2Sc6XnGaUu6qb3hI=";
        final String base64AuthData = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMALQr6E/bsTVnj2wDNeBSjfaQsfNF93xqo6nkZoel1CW5ZjxdzAoOiL9UTgxfdPaUBAgMmIAEhWCDH7Ugz3uf/f5ghXaaVDIM/s9eARc/E86/ukagnsSoqSCJYIBGMhZ/Z0v1BrG6S9opII2DW5hWOkWo7Aw8xaLjNenyT";
        byte[] signatureFromClient = decoder.decode(base64Signature);
        byte[] authenticatorData = decoder.decode(base64AuthData);

        byte[] idLenBytes = Arrays.copyOfRange(authenticatorData, 53, 55);
        int idLen = Integer.parseInt(new BigInteger(idLenBytes).toString(16), 16);
        byte[] pubKeyCBOR = Arrays.copyOfRange(authenticatorData, 55 + idLen, authenticatorData.length);

        // generate clientDataHash
        String base64ClientDataJSON = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZUZkUlozQnRSMkpoVHpSb2JrRklVbFZtTm1aZlJHRmZia2xWIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==";
        byte[] clientDataHash = hash(base64ClientDataJSON);
        ClientData clientData = new ObjectMapper().readValue(decoder.decode(base64ClientDataJSON), new TypeReference<>() {});

        // make a message to verify the signature with alg
        byte[] message = getMessage(authenticatorData, clientDataHash);

        // get publicKey from Authenticator Data
        String keyType = getKeyType(pubKeyCBOR);
        if(keyType.equals("EC")) {
            PublicKeySource publicKeySource = getPublicKeySource(pubKeyCBOR, "testID");
            PublicKey pubKey = getPublicKey(publicKeySource);
            Signature signature = getECSignature(publicKeySource);
            signature.initVerify(pubKey);
            signature.update(message);
            boolean verified = signature.verify(signatureFromClient);
            if(verified) {
                System.out.println("SAVE KEYSOURCE");
                // keySourceRepository.save(publicKeySource);
                // return jwt or something
            } else {
                System.err.println("THROW EXCEPTION");
                // throw exception
            }
        }
        else if(keyType.equals("RSA")) {
            System.out.println("RSA NOT READY");
        }
    }

    private String getKeyType(byte[] pubKeyCBOR) throws IOException {
        String pubKeyString = stringifyCBOR(pubKeyCBOR);
        if (pubKeyString.contains("\"1\":2")) {
            return "EC";
        }
        else if(pubKeyString.contains("\"1\":3")) {
            return "RSA";
        }
        throw new IllegalArgumentException("지원하지 않은 키타입");
    }

    private PublicKey getPublicKey(PublicKeySource publicKeySource) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        switch (publicKeySource.getOne()) {
            case "2" : {
                EcPublicKeyObject ecPublicKeyObject = new EcPublicKeyObject(publicKeySource);
                return getEcPublicKey(ecPublicKeyObject);
            }
            case "3" : {
                RsaPublicKeyObject rsaPublicKeyObject = new RsaPublicKeyObject(publicKeySource);
                return getRsaPublicKey(rsaPublicKeyObject);
            }
        }
        throw new RuntimeException("test");
    }
    private PublicKey getEcPublicKey(EcPublicKeyObject ecPublicKeyObject) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        ECGenParameterSpec parameterSpec = new ECGenParameterSpec(getStandardNameOfCurveType(ecPublicKeyObject));
        parameters.init(parameterSpec);

        BigInteger x = new BigInteger(1, decoder.decode(ecPublicKeyObject.xCoordinate));
        BigInteger y = new BigInteger(1, decoder.decode(ecPublicKeyObject.yCoordinate));
        ECPoint ecPoint = new ECPoint(x, y);

        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(publicKeySpec);
    }

    private PublicKey getRsaPublicKey(RsaPublicKeyObject rsaPublicKeyObject) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger modulus = new BigInteger(1, decoder.decode(rsaPublicKeyObject.n));
        BigInteger exponent = new BigInteger(1, decoder.decode(rsaPublicKeyObject.e));
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(rsaPublicKeySpec);
    }

    private static PublicKeySource getPublicKeySource(byte[] pubKeyCBOR, String userId) throws IOException {
        PublicKeySource publicKeySource = new ObjectMapper().readValue(stringifyCBOR(pubKeyCBOR), new TypeReference<>() {});
        publicKeySource.setUserId(userId);
        return publicKeySource;
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
     * reference from
     * 1. RFC8152 SECTION 8.1
     * 2. https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunEC
     */
    private static Signature getECSignature(PublicKeySource publicKeySource) throws NoSuchAlgorithmException, NoSuchProviderException {
        if ("-7".equals(publicKeySource.getThree())) {
            return Signature.getInstance("SHA256withECDSA", "SunEC");
        }
        throw new IllegalArgumentException("not supported alg");
    }

    /**
     * RFC8152 SECTION 2
     * https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#signature-algorithms
     */
    private static Signature getRSASignature(PublicKeySource publicKeySource) throws NoSuchAlgorithmException, NoSuchProviderException {
        if ("-37".equals(publicKeySource.getThree())) {
            return Signature.getInstance("SHA256withRSA/PSS", "SunRsaSign");
        }
        throw new IllegalArgumentException("not supported alg");
    }

    private static byte[] getMessage(byte[] decodedAuthData, byte[] clientDataHash) {
        return ByteBuffer.allocate(decodedAuthData.length + clientDataHash.length)
                .put(decodedAuthData)
                .put(clientDataHash)
                .array();
    }
    private static byte[] hash(String clientDataJson) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
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
        String keyType;
        String alg;
        String curveType;
        String xCoordinate;
        String yCoordinate;
        EcPublicKeyObject(PublicKeySource keyObject) {
            this.keyType = keyObject.getOne();
            this.alg = keyObject.getThree();
            this.curveType = keyObject.getMinusOne();
            this.xCoordinate = keyObject.getMinusTwo();
            this.yCoordinate = keyObject.getMinusThree();
        }
    }

    static class RsaPublicKeyObject {
        String keyType;
        String alg;
        String n;
        String e;
        RsaPublicKeyObject(PublicKeySource keyObject) {
            this.keyType = keyObject.getOne();
            this.alg = keyObject.getThree();
            this.n = keyObject.getMinusOne();
            this.e = keyObject.getMinusTwo();
        }
    }

}
