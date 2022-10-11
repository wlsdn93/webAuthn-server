package com.practice.fido.webAuthn.service;

import com.fasterxml.jackson.annotation.JsonProperty;
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
import com.practice.fido.webAuthn.entity.domain.EcPublicKeySource;
import com.practice.fido.webAuthn.entity.domain.User;
import com.practice.fido.webAuthn.repository.ChallengeRepository;
import com.practice.fido.webAuthn.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Service
@Slf4j
@Transactional
public class WebAuthnService {

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

    public String getChallenge() {
        byte[] buffer = new byte[20];
        random.nextBytes(buffer);
        return encoder.encodeToString(buffer);
    }

    public PubKeyCredCreatingOptions getCredentialOptions() {
        //challenge
        String challenge = getChallenge();

        //rp
        String rpName = "x8byte security";
        String rpId = "localhost";
        RelyingParty rp = new RelyingParty(rpName, rpId);

        String userId = "g-BuqvgcZ2VAhx_QAm7KSw";
        User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("존해하지 않는 사용자"));
        String name = user.getUsername();
        String displayName = user.getDisplayName();
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
    public boolean attestPublicKeyCredential(PublicKeyCredential credential) throws IOException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, SignatureException {
        // parse credential to get clientData & attestationObject
        ClientData clientData = parseClientData(credential.getClientDataJSON());
        Attestation attestation = parseAttestation(credential.getAttestationObject());
        byte[] authData = decoder.decode(attestation.authData);

        // client data 에서 origin, challenge, type 확인
        challengeRepository.findById(clientData.challenge).orElseThrow(() -> new RuntimeException("유효하지 않는 챌린지"));
        challengeRepository.deleteById(clientData.challenge);

        boolean isValidOrigin = clientData.origin.equals("localhost:8081");
        

        // if x5c not exist : self attestation

        if(attestation.attStmt.getX5c().isBlank()) {
            // 1. authData.alg 와 attStmt.alg 가 같은지 비교
            byte[] idLenBytes = Arrays.copyOfRange(authData, 53, 55);
            int idLen = Integer.parseInt(new BigInteger(idLenBytes).toString(16), 16);
            byte[] publicKeyObjectFromAuthData = Arrays.copyOfRange(authData, 55 + idLen, authData.length);
            EcPublicKeyJson publicKeyJson = parsePublicKeyObject(publicKeyObjectFromAuthData);
            if (!publicKeyJson.alg.equals(attestation.attStmt.getAlg())) {
                throw new RuntimeException("Authenticator and Attestation Statement Algorithm doesn't match");
            }

            // 2. attStmt.sig 를 authData 와 clientData 그리고 public key 를 이용해서 검증
            byte[] clientDataHash = hash("SHA-256", credential.getClientDataJSON());
            byte[] message = getMessage(authData, clientDataHash);
            PublicKey pubKey = getECPublicKey(publicKeyJson);
            String base64EncodedSignature = attestation.attStmt.getSig();
            byte[] signature = decoder.decode(base64EncodedSignature);

            boolean isValidSignature = verifySignature(signature, message, pubKey);

            if(isValidSignature) {
                // 1. public-key DB에 저장
                // 2. jwt 발급 / refresh token 발급 ?
                return true;
            } else {
                // 3. self attestation 을 했다는 것을 표현하는 정보를 검증 결과로 반환해야함
                throw new RuntimeException("Failed to verify the signature");
            }
        } else {
            throw new RuntimeException("The server is only supporting self attestation for now");
        }
    }
    private boolean verifySignature(byte[] signature, byte[] message, PublicKey pubKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signatureVerifier = Signature.getInstance("SHA256withECDSA", "SunEC");
        signatureVerifier.initVerify(pubKey);
        signatureVerifier.update(message);
        return signatureVerifier.verify(signature);
    }

    private PublicKey getECPublicKey(EcPublicKeyJson publicKeyJson) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {

        byte[] minus2 = decoder.decode(publicKeyJson.xCoordinate);
        byte[] minus3 = decoder.decode(publicKeyJson.yCoordinate);

        BigInteger x = new BigInteger(1, minus2);
        BigInteger y = new BigInteger(1, minus3);

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        ECGenParameterSpec parameterSpec = new ECGenParameterSpec("secp256r1");
        parameters.init(parameterSpec);

        ECPoint ecPoint = new ECPoint(x, y);
        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(publicKeySpec);
    }

    private EcPublicKeyJson parsePublicKeyObject(byte[] publicKeyObject) throws IOException {
        return new ObjectMapper().readValue(stringifyCBOR(publicKeyObject), new TypeReference<>() {});
    }

    private byte[] getMessage(byte[] decodedAuthData, byte[] clientDataHash) {
        return ByteBuffer.allocate(decodedAuthData.length + clientDataHash.length)
                .put(decodedAuthData)
                .put(clientDataHash)
                .array();
    }

    private ClientData parseClientData(String clientDataJSON) throws JsonProcessingException {
        log.info("clientDataJSON : {}", clientDataJSON);
        String decodedClientData = new String(decoder.decode(clientDataJSON), StandardCharsets.UTF_8);
        return objMapper.readValue(decodedClientData, new TypeReference<>() {
        });
    }

    private Attestation parseAttestation(String base64EncodedCborAttestation) throws IOException {
        log.info("attestation : {}", base64EncodedCborAttestation);
        byte[] attestationObject = decoder.decode(base64EncodedCborAttestation);
        return objMapper.readValue(stringifyCBOR(attestationObject), new TypeReference<>() {
        });
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

    private static byte[] hash(String alg, String clientDataJson) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(alg);
        md.update(decoder.decode(clientDataJson));
        return md.digest();
    }

    static class EcPublicKeyJson {
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
