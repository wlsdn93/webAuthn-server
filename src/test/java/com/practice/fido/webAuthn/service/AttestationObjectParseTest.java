package com.practice.fido.webAuthn.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.fido.webAuthn.dto.registration.Attestation;
import com.practice.fido.webAuthn.entity.PublicKeySource;
import com.practice.fido.webAuthn.vo.RSAPublicKeyVO;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.UUID;

import static com.practice.fido.webAuthn.util.WebAuthnUtil.*;

public class AttestationObjectParseTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Test
    @DisplayName("Attestation 파싱 테스트")
    void QRLoginTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQAlDelD98ZIlynYHLyps75tOKRfSESXmIDfizRMFKzWA/KHUf+0Pjdw2bsBi1jTYcGinKtp0/dPHJDnkdgInzYvXZuEISp+GeQAOmmFWCAPh2kQbsAEfuMWZpKR4H7RGD0XbYdFrZVwtrasZU4r1YKM2euK3SEs5eZ4WGe4CIzjwu/qeJSn4GMah4zpcJS0rs+ZsjLVR8Ln1iwfLEw/FaQcpuv9FUWpua4wkGmGy4wEJZpMEZ5Zx8c5YGQGEGa7Y/yvYWdV311zDoX13xhDADBJLUPkqaLbJeamoKoAMNUJEi3ERw3YSMRuk27T3K/L1YrLeQ1Xq62/2GaH4694VoFsaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAiYcFjK3EuBtuEw3lDcvpYAIJ56T+uQQxDYLmo8qkBb70H92s0u+B62auy8EnKVarA+pAEDAzkBACBZAQDCEgGvb9+bxu8RlCZLQwMqgQz/NB1rrt5wlJDaoygoN/3Dga8ltXnxY9pSq4NEun7mJDBPj+PFkUrhWOrFYTsu7Y+Y1SfWMiDKBnA8jHbJ71aSwtHrgsPAuTRIBf8ZSCtdzX6QdiaxzRnxvuBwPEc77FhuuKXJiYyO70kxOpWTbC0KH5Siqy2ZEnSB3Fyx+k7GU9ZER8ANcor8lC4IxHdsxEJS7EOYe+LotZrBeOfFvfZ/50OyRpvhQJWqIvS6BVrhjBFG4hJH9ZygEcon+jCvKSWhfJ9pqvktpb4j/gk6sQNjSNyrGKYapDJ4b1UFcbEbrnmA6Raz6MxAjSXQfCmhIUMBAAE=";
        String a = stringifyCBOR(decodeBase64(attestationObject));
        System.out.println("AttestationObject = " + a);

        Attestation attestation = objectMapper.readValue(a, new TypeReference<>() {
        });
        byte[] authData = decodeBase64(attestation.authData);
        byte[] aaguid = Arrays.copyOfRange(authData, 37, 53);
        ByteBuffer bb = ByteBuffer.wrap(aaguid);
        UUID uuid = new UUID(bb.getLong(), bb.getLong());
        System.out.println("aaguid = " + uuid);
        byte[] idLenBytes = Arrays.copyOfRange(authData, 53, 55);
        int idLen = Integer.parseInt(new BigInteger(idLenBytes).toString(16), 16);
        byte[] pubKeyCBOR = Arrays.copyOfRange(authData, 55 + idLen, authData.length);
        PublicKeySource publicKeySource =  new ObjectMapper().readValue(stringifyCBOR(pubKeyCBOR), new TypeReference<>() {});
        System.out.println("publicKeySource.getKeyType() = " + publicKeySource.getKeyType());
        System.out.println("1 = " + publicKeySource.getOne());
        System.out.println("3 = " + publicKeySource.getThree());
        System.out.println("-1 = " + publicKeySource.getMinusOne());
        System.out.println("-2 = " + publicKeySource.getMinusTwo());
        RSAPublicKeyVO rsaPublicKeyVO = new RSAPublicKeyVO(publicKeySource);
        BigInteger modulus = rsaPublicKeyVO.getModulus();
        BigInteger exponent = rsaPublicKeyVO.getExponent();
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);

        int i = publicKey.getModulus().bitLength();
        System.out.println("key bit = " + i);
        System.out.println("fmt : " + attestation.fmt);
        System.out.println("attStmt.alg : " + attestation.attStmt.getAlg());
        System.out.println("attStmt.x5c : " + attestation.attStmt.getX5c());
        System.out.println("attStmt.sig : " + attestation.attStmt.getSig());
        System.out.println("authData : " + attestation.authData);
    }

}
