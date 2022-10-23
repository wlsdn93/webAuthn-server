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
        String attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAJ6YxP4HeN5coZExWHK841mRBjKSgp92NJwlGH0zZ8Z0AiEAz3Rv6i9FIHvUYhiFwQhaj3bu3TGqRODdxMMrvCRBCkFoYXV0aERhdGFYpEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAACtzgACNbzGCmSLCyXx8FUDACAe4GEJqHpbUZsSiKBLg9wWDf4BDuVLgZCrtQGY4j2hiKUBAgMmIAEhWCDKjdlW1zGPg6R53ipMjYuSNCGqLw8LggKNH02Ej1iCnCJYIJiYxtfBde8++oBygk90pFQmQbY9N8BZbYs01KTH7euC";
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
