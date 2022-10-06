package com.practice.fido.webAuthn.service;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

public class WebAuthnServiceTest {

    @Autowired
    WebAuthnService webAuthnService;
    static Base64.Decoder decoder = Base64.getDecoder();
    @Test
    @DisplayName("JSON 파싱 확인하기")
    public void parseAttestationObject() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        String mockSignature = "MEUCIQDL4GqDMhphN0clc7lVV87KG0CpstF/uEakF8n1Shln1QIgbMwnGqhbW1YDxofp4UrhPU3x+WX2Sc6XnGaUu6qb3hI=";
        String mockAuthData = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMALQr6E/bsTVnj2wDNeBSjfaQsfNF93xqo6nkZoel1CW5ZjxdzAoOiL9UTgxfdPaUBAgMmIAEhWCDH7Ugz3uf/f5ghXaaVDIM/s9eARc/E86/ukagnsSoqSCJYIBGMhZ/Z0v1BrG6S9opII2DW5hWOkWo7Aw8xaLjNenyT";
        byte[] decodedSignature = decoder.decode(mockSignature);
        byte[] decodedAuthData = decoder.decode(mockAuthData);

        byte[] idLenBytes = Arrays.copyOfRange(decodedAuthData, 53, 55);
        int idLen = Integer.parseInt(new BigInteger(idLenBytes).toString(16), 16);
        byte[] publicKeyObject = Arrays.copyOfRange(decodedAuthData, 55 + idLen, decodedAuthData.length);

        // get publicKey from Authenticator Data
        PublicKeyJson publicKeyJson = new ObjectMapper().readValue(stringifyCBOR(publicKeyObject), new TypeReference<>() {});
        byte[] minus2 = decoder.decode(publicKeyJson.xCoordinate);
        byte[] minus3 = decoder.decode(publicKeyJson.yCoordinate);


        BigInteger x = new BigInteger(1, minus2);
        BigInteger y = new BigInteger(1, minus3);

        System.out.println("x = " + x + "\ny = " + y);

        ECPoint ecPoint = new ECPoint(x, y);
        ECGenParameterSpec parameterSpec = new ECGenParameterSpec("secp256r1");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(parameterSpec);
        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);

        // generate clientDataHash
        String mockClientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZUZkUlozQnRSMkpoVHpSb2JrRklVbFZtTm1aZlJHRmZia2xWIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==";
        byte[] clientDataHash = hash("SHA-256", mockClientDataJson);


        // make a message to verify the signature with alg
        byte[] message = ByteBuffer.allocate(decodedAuthData.length + clientDataHash.length)
                .put(decodedAuthData)
                .put(clientDataHash)
                .array();

        System.out.println("decodedAuthData = " + Arrays.toString(decodedAuthData));
        System.out.println("clientDataHash = " + Arrays.toString(clientDataHash));
        System.out.println("message = " + Arrays.toString(message));


        // verify the signature
        Signature signature = Signature.getInstance("SHA256withECDSA", "SunEC");
        signature.initVerify(pubKey);
        signature.update(message);
        boolean verify = signature.verify(decodedSignature);
        System.out.println("verify = " + verify);

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

    static class PublicKeyJson {
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
