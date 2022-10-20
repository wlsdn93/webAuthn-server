package com.practice.fido.webAuthn.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.fido.webAuthn.dto.ECPublicKeyVO;
import com.practice.fido.webAuthn.dto.PubKeyCredCreatingOptions;
import com.practice.fido.webAuthn.dto.PublicKeyCredential;
import com.practice.fido.webAuthn.dto.RSAPublicKeyVO;
import com.practice.fido.webAuthn.entity.auth.*;
import com.practice.fido.webAuthn.entity.domain.PublicKeySource;
import com.practice.fido.webAuthn.repository.ChallengeRepository;
import com.practice.fido.webAuthn.repository.PublicKeySourceRepository;
import com.practice.fido.webAuthn.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static com.practice.fido.webAuthn.entity.auth.AuthenticatorSelection.*;
import static com.practice.fido.webAuthn.util.WebAuthnUtil.hash;
import static com.practice.fido.webAuthn.util.WebAuthnUtil.stringifyCBOR;

@Service
@Slf4j
@Transactional
public class WebAuthnService {

    private static final SecureRandom random = new SecureRandom();
    private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private static final ObjectMapper objMapper = new ObjectMapper();
    private final ChallengeRepository challengeRepository;

    private final PublicKeySourceRepository keySourceRepository;
    private final UserRepository userRepository;

    public WebAuthnService(ChallengeRepository challengeRepository,
                           PublicKeySourceRepository keySourceRepository,
                           UserRepository userRepository) {
        this.challengeRepository = challengeRepository;
        this.keySourceRepository = keySourceRepository;
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

//        String userId = "g-BuqvgcZ2VAhx_QAm7KSw";
//        User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("존해하지 않는 사용자"));
//        String name = user.getUsername();
//        String displayName = user.getDisplayName();
        String userId = "BuqvgcZ2VAhx_QAm7KSw";
        String name = "test";
        String displayName = "dokke";
        UserInfo userInfo = new UserInfo(userId, name, displayName);

        //pubKeyCredParams
        List<PubKeyCredParams> pubKeyCredParams = new ArrayList<>();
        pubKeyCredParams.add(new PubKeyCredParams(-7, "public-key"));
        pubKeyCredParams.add(new PubKeyCredParams(-257, "public-key"));

        //authenticationSelection
        AuthenticatorSelection authenticatorSelection =
                new AuthenticatorSelection(AuthenticatorAttachment.PLATFORM,
                                            UserVerification.PREFERRED,
                                            ResidentKey.PREFERRED,
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
        byte[] signatureFromClient = decoder.decode(attestation.attStmt.getSig());
        // client data 에서 origin, challenge, type 확인
//        challengeRepository.findById(clientData.challenge).orElseThrow(() -> new RuntimeException("유효하지 않는 챌린지"));
//        challengeRepository.deleteById(clientData.challenge);

//        if (!clientData.origin.equals("localhost:8081")) {
            log.info(clientData.origin);
//            throw new IllegalArgumentException("NOT VALID ORIGIN");
//        };

        PublicKeySource publicKeySource = getPublicKeySource(authData);
        // if x5c not exist : self attestation
        String x5c = attestation.attStmt.getX5c();
        if(x5c.isBlank()) {
            // 1. authData.alg 와 attStmt.alg 가 같은지 비교
//            EcPublicKeyJson publicKeyJson = parsePublicKeyObject(pubKeyCBOR);
//            if (!publicKeyJson.alg.equals(attestation.attStmt.getAlg())) {
//                throw new RuntimeException("Authenticator and Attestation Statement Algorithm doesn't match");
//            }

            // 2. attStmt.sig 를 authData 와 clientData 그리고 public key 를 이용해서 검증
            byte[] clientDataHash = hash(credential.getClientDataJSON());
            byte[] message = getMessage(authData, clientDataHash);
            String keyType = publicKeySource.getKeyType();

            // 3.
            PublicKey publicKey = getPublicKey(publicKeySource);
            Signature signature = null;
            if(keyType.equals("EC")) {
                signature = getECSignature(publicKeySource);
            } else if(keyType.equals("RSA")) {
                signature = getRSASignature(publicKeySource);
            }
            signature.initVerify(publicKey);
            signature.update(message);
            boolean verify = signature.verify(signatureFromClient);
            if (verify) {
                log.info("=== success ===");
                log.info("SAVE KEY SOURCE");
//                publicKeySource.setUserId(userId);
//                keySourceRepository.save(publicKeySource);
                log.info("return JWT");
            }
        } else {
            log.info("=== fail ===");
            throw new RuntimeException("The server is only supporting self attestation for now");
        }
        return false;
    }

    private PublicKey getPublicKey(PublicKeySource publicKeySource) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        switch (publicKeySource.getOne()) {
            case "2" : {
                ECPublicKeyVO ecPublicKeyVO = new ECPublicKeyVO(publicKeySource);
                return getEcPublicKey(ecPublicKeyVO);
            }
            case "3" : {
                RSAPublicKeyVO rsaPublicKeyVO = new RSAPublicKeyVO(publicKeySource);
                return getRsaPublicKey(rsaPublicKeyVO);
            }
        }
        throw new RuntimeException("test");
    }

    private PublicKey getEcPublicKey(ECPublicKeyVO ecPublicKeyVO) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        ECGenParameterSpec parameterSpec = new ECGenParameterSpec(ecPublicKeyVO.getStandardNameOfCurveType());
        parameters.init(parameterSpec);

        BigInteger x = ecPublicKeyVO.getXCoordinate();
        BigInteger y = ecPublicKeyVO.getYCoordinate();
        ECPoint ecPoint = new ECPoint(x, y);

        ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(publicKeySpec);
    }

    private PublicKey getRsaPublicKey(RSAPublicKeyVO rsaPublicKeyVO) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger modulus = rsaPublicKeyVO.getModulus();
        BigInteger exponent = rsaPublicKeyVO.getExponent();
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(rsaPublicKeySpec);
    }

    private PublicKeySource getPublicKeySource(byte[] authData) throws IOException {
        byte[] idLenBytes = Arrays.copyOfRange(authData, 53, 55);
        int idLen = Integer.parseInt(new BigInteger(idLenBytes).toString(16), 16);
        byte[] pubKeyCBOR = Arrays.copyOfRange(authData, 55 + idLen, authData.length);
        PublicKeySource publicKeySource = new ObjectMapper().readValue(stringifyCBOR(pubKeyCBOR), new TypeReference<>() {});
        return publicKeySource;
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

    private static Signature getECSignature(PublicKeySource publicKeySource) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (publicKeySource.getThree().equals("-7")) {
            return Signature.getInstance("SHA256withECDSA", "SunEC");
        }
        throw new IllegalArgumentException("not supported alg");
    }

    private static Signature getRSASignature(PublicKeySource publicKeySource) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (publicKeySource.getThree().equals("-37")) {
            return Signature.getInstance("SHA256withRSA/PSS", "SunRsaSign");
        }
        throw new IllegalArgumentException("not supported alg");
    }

}
