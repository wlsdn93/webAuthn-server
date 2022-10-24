package com.practice.fido.webAuthn.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.fido.webAuthn.dto.registration.Attestation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.practice.fido.webAuthn.util.WebAuthnUtil.*;

public class AttestationObjectParseTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Test
    @DisplayName("Attestation 파싱 테스트")
    void QRLoginTest() throws IOException {
        String attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQAlDelD98ZIlynYHLyps75tOKRfSESXmIDfizRMFKzWA/KHUf+0Pjdw2bsBi1jTYcGinKtp0/dPHJDnkdgInzYvXZuEISp+GeQAOmmFWCAPh2kQbsAEfuMWZpKR4H7RGD0XbYdFrZVwtrasZU4r1YKM2euK3SEs5eZ4WGe4CIzjwu/qeJSn4GMah4zpcJS0rs+ZsjLVR8Ln1iwfLEw/FaQcpuv9FUWpua4wkGmGy4wEJZpMEZ5Zx8c5YGQGEGa7Y/yvYWdV311zDoX13xhDADBJLUPkqaLbJeamoKoAMNUJEi3ERw3YSMRuk27T3K/L1YrLeQ1Xq62/2GaH4694VoFsaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAiYcFjK3EuBtuEw3lDcvpYAIJ56T+uQQxDYLmo8qkBb70H92s0u+B62auy8EnKVarA+pAEDAzkBACBZAQDCEgGvb9+bxu8RlCZLQwMqgQz/NB1rrt5wlJDaoygoN/3Dga8ltXnxY9pSq4NEun7mJDBPj+PFkUrhWOrFYTsu7Y+Y1SfWMiDKBnA8jHbJ71aSwtHrgsPAuTRIBf8ZSCtdzX6QdiaxzRnxvuBwPEc77FhuuKXJiYyO70kxOpWTbC0KH5Siqy2ZEnSB3Fyx+k7GU9ZER8ANcor8lC4IxHdsxEJS7EOYe+LotZrBeOfFvfZ/50OyRpvhQJWqIvS6BVrhjBFG4hJH9ZygEcon+jCvKSWhfJ9pqvktpb4j/gk6sQNjSNyrGKYapDJ4b1UFcbEbrnmA6Raz6MxAjSXQfCmhIUMBAAE=";
        String a = stringifyCBOR(decodeBase64(attestationObject));
        System.out.println("AttestationObject = " + a);

        Attestation attestation = objectMapper.readValue(a, new TypeReference<>() {
        });
        System.out.println("fmt : " + attestation.fmt);
        System.out.println("attStmt.alg : " + attestation.attStmt.getAlg());
        System.out.println("attStmt.x5c : " + attestation.attStmt.getX5c());
        System.out.println("attStmt.sig : " + attestation.attStmt.getSig());
        System.out.println("authData : " + attestation.authData);
    }

}
