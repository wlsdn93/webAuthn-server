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
import java.nio.charset.StandardCharsets;
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
        String sig = "MEUCIG1woNzPxi/1Kga7PeMHLfZHgcKGD6gHcHnhjDtivMe2AiEA3snRANE1hCwvMSTxwZxIyUt61WGDggcVHol6x+cVxfo=";
        String authData = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAK3OAAI1vMYKZIsLJfHwVQMALQLrCx4Ysi2kDMgBe625L/VTwp4x15pOM9zQki2LQ5DKQHMtL2yF8e3vsVm9y6UBAgMmIAEhWCCY19fn+dGOG93ObKtWSUHtOtnkD3N/MZMOFAV2PB7A1iJYIA9zbQafhp/pXUL6DgNuLIZ4fIzs34cT4qETWXmiSOTo";
        String credentialId = "AusLHhiyLaQMyAF7rbkv9VPCnjHXmk4z3NCSLYtDkMpAcy0vbIXx7e-xWb3L";
        byte[] dsig = decoder.decode(sig);
        byte[] dAuth = decoder.decode(authData);
//        byte[] dCId = decoder.decode(credentialId);

        System.out.println("dAuth = " + Arrays.toString(dAuth));
        System.out.println(dAuth.length);
        System.out.println();
//        System.out.println("dCId = " + Arrays.toString(dCId));
//        System.out.println(dCId.length);
        System.out.println();
//        System.out.println("dsig = " + Arrays.toString(dsig));
//        System.out.println(dsig.length);
        byte[] AAGUID = Arrays.copyOfRange(dAuth, 36, 53);
        System.out.println("AAGUID : " + Arrays.toString(AAGUID));
        byte[] idLenBytes = Arrays.copyOfRange(dAuth, 53, 55);
        int idLen = Integer.parseInt(new BigInteger(idLenBytes).toString(16), 16);
        System.out.println("IdLen = " + idLen);


//         AusLHhiyLaQMyAF7rbkv9VPCnjHXmk4z3NCSLYtDkMpAcy0vbIXx7e-xWb3L // maqybe credential id
        byte[] credentialIdBytes = Arrays.copyOfRange(dAuth, 55, 55 + idLen);
        System.out.println("credentialId = " + Arrays.toString(credentialIdBytes));


        byte[] publicKeyObject = Arrays.copyOfRange(dAuth, 55 + idLen, dAuth.length);
        System.out.println("publicKeyObject = " + Arrays.toString(publicKeyObject));

        System.out.println(stringifyCBOR(publicKeyObject));
        byte[] minus2 = decoder.decode("mNfX5/nRjhvdzmyrVklB7TrZ5A9zfzGTDhQFdjwewNY=");
        byte[] minus3 =  decoder.decode("D3NtBp+Gn+ldQvoOA24shnh8jOzfhxPioRNZeaJI5Og=");
        System.out.println("-2 L : " + minus2.length);
        System.out.println("-2 : " + Arrays.toString(minus2));
        System.out.println("-3 L : " + minus3.length);
        System.out.println("-3 : " + Arrays.toString(minus3));

        PublicKey publicKey = new ObjectMapper().readValue(stringifyCBOR(publicKeyObject), new TypeReference<>() {
        });

        System.out.println("keyType : " + publicKey.keyType);
        System.out.println("alg : " + publicKey.alg);
        System.out.println("curveType : " + publicKey.curveType);
        System.out.println("xCoordinate : " + publicKey.xCoordinate);
        System.out.println("yCoordinate : " + publicKey.yCoordinate);
        BigInteger x = new BigInteger(1, minus2);
        BigInteger y = new BigInteger(1, minus3);
        System.out.println(x);
        System.out.println(y);

        ECPoint ecPoint = new ECPoint(x, y);
        ECGenParameterSpec parameterSpec = new ECGenParameterSpec("secp256r1");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(parameterSpec);
        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        java.security.PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);




        // generate clientDataHash
        String clientDataJson = "{\n" +
                "  \"origin\" : \"http://localhost:8081\",\n" +
                "  \"challenge\" : \"YU55NDItQmJ1bXREQkhIdEN1UWVJTkhDQ0VZ\",\n" +
                "  \"crossOrigin\" : false,\n" +
                "  \"type\" : \"webauthn.create\"\n" +
                "}";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(clientDataJson.getBytes());
        String clientDataHash = bytesToHex(md.digest());

        // signature verify
//        Signature signature = Signature.getInstance("SHA256withECDSA", "SunEC");
//        signature.initVerify(pubKey);
//        signature.update();
//        signature.verify(dsig);


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

    private String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    static class PublicKey {
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
