package com.practice.fido.webAuthn.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.fido.webAuthn.dto.AuthenticationPublicKeyCredential;
import com.practice.fido.webAuthn.dto.authentication.AllowCredential;
import com.practice.fido.webAuthn.dto.authentication.PublicKeyCredRequestOptions;
import com.practice.fido.webAuthn.dto.common.*;
import com.practice.fido.webAuthn.dto.registration.*;
import com.practice.fido.webAuthn.vo.ECPublicKeyVO;
import com.practice.fido.webAuthn.dto.registration.PubKeyCredCreatingOptions;
import com.practice.fido.webAuthn.dto.RegistrationPublicKeyCredential;
import com.practice.fido.webAuthn.vo.RSAPublicKeyVO;
import com.practice.fido.webAuthn.entity.PublicKeySource;
import com.practice.fido.webAuthn.repository.ChallengeRepository;
import com.practice.fido.webAuthn.repository.PublicKeySourceRepository;
import com.practice.fido.webAuthn.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.practice.fido.webAuthn.dto.authentication.AllowCredential.*;
import static com.practice.fido.webAuthn.dto.registration.AuthenticatorSelection.*;
import static com.practice.fido.webAuthn.util.WebAuthnUtil.*;

@Service
@Slf4j
@Transactional
public class WebAuthnService {

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

    public PublicKeyCredRequestOptions getCredentialRequestOptions() {
        PublicKeySource publicKeySource = keySourceRepository
                .findByUserId("BuqvgcZ2VAhx_QAm7KSw")
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 키"));
        publicKeySource.getCredentialId();
        // credential 마다 allow transport 를 따로 해야하나?
        List<AuthenticatorTransport> transports = List.of(new AuthenticatorTransport[]{AuthenticatorTransport.INTERNAL});
        Challenge challenge = generateChallenge();
        AllowCredential allowCredential = new AllowCredential(publicKeySource.getCredentialId(), transports);
        List<AllowCredential> allowCredentials = List.of(new AllowCredential[]{allowCredential});
        return PublicKeyCredRequestOptions.builder()
                .allowCredentials(allowCredentials)
                .challenge(challenge.toString())
                .userVerification("preferred")
                .rpId("localhost")
                .build();
    }

    public PubKeyCredCreatingOptions getCredentialCreatingOptions() {
        //challenge
        Challenge challenge = generateChallenge();
        log.info("issued challenge : {}", challenge);
        challengeRepository.save(challenge);
        //rp
        String rpName = "x8byte security";
        String rpId = "localhost";
        RelyingParty rp = new RelyingParty(rpName, rpId);

//        String userId = "g-BuqvgcZ2VAhx_QAm7KSw";
//        User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자"));
//        String name = user.getUsername();
//        String displayName = user.getDisplayName();
        String userId = "BuqvgcZ2VAhx_QAm7KSw";
        String name = "dokke";
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
                .challenge(challenge.toString())
                .relyingParty(rp)
                .user(userInfo)
                .pubKeyCredParams(pubKeyCredParams)
                .authenticatorSelection(authenticatorSelection)
                .build();
    }
    public boolean attestPublicKeyCredential(RegistrationPublicKeyCredential credential) throws IOException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, SignatureException {


        // parse credential to get clientData & attestationObject
        ClientData clientData = parseClientData(credential.getClientDataJSON());
        Attestation attestation = parseAttestation(credential.getAttestationObject());
        byte[] authData = decodeBase64(attestation.authData);
        if (attestation.fmt.equals("none")) {
            PublicKeySource publicKeySource = getPublicKeySource(authData);
            publicKeySource.setCredentialId(credential.getId());
            publicKeySource.setUserId("BuqvgcZ2VAhx_QAm7KSw");
            keySourceRepository.save(publicKeySource);
            return true;
        }
        byte[] signatureFromClient = decodeBase64(attestation.attStmt.getSig());

        doClientDataValidation(clientData);

        PublicKeySource publicKeySource = getPublicKeySource(authData);
        // if x5c not exist : self attestation
        String x5c = attestation.attStmt.getX5c();
        if(x5c.isBlank()) {
            // 1. authData.alg 와 attStmt.alg 가 같은지 비교
            String authDataAlg = publicKeySource.getThree();
            String attStmtAlg = attestation.attStmt.getAlg();
            if (!authDataAlg.equals(attStmtAlg)) {
                throw new RuntimeException("Alg not match");
            }

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
                publicKeySource.setCredentialId(credential.getId());
                publicKeySource.setUserId("BuqvgcZ2VAhx_QAm7KSw");
                keySourceRepository.save(publicKeySource);
            }
        } else {
            log.info("=== fail ===");
            throw new RuntimeException("self attestation 만 지원하고 있음");
        }
        return false;
    }

    // client data 에서 origin, challenge, type 확인
    private void doClientDataValidation(ClientData clientData) {
        if(!clientData.origin.equals("http://localhost:8081")) {
            throw new RuntimeException("허용하지 않는 오리진");
        }

        if (!clientData.type.equals("webauthn.create")) {
            throw new RuntimeException("요청타입이 webauthn.create 이 아님");
        }

        String challenge = clientData.getChallenge();
        challengeRepository.findById(challenge).orElseThrow(() -> new RuntimeException("유효하지 않은 챌린지"));
        challengeRepository.deleteById(challenge);
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
        throw new RuntimeException("EC, RSA 키타입이 아님");
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
        return KeyFactory.getInstance("EC").generatePublic(publicKeySpec);

    }

    private PublicKey getRsaPublicKey(RSAPublicKeyVO rsaPublicKeyVO) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger modulus = rsaPublicKeyVO.getModulus();
        BigInteger exponent = rsaPublicKeyVO.getExponent();
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        return KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
    }

    private PublicKeySource getPublicKeySource(byte[] authData) throws IOException {
        byte[] idLenBytes = Arrays.copyOfRange(authData, 53, 55);
        int idLen = Integer.parseInt(new BigInteger(idLenBytes).toString(16), 16);
        byte[] pubKeyCBOR = Arrays.copyOfRange(authData, 55 + idLen, authData.length);
        return new ObjectMapper().readValue(stringifyCBOR(pubKeyCBOR), new TypeReference<>() {});
    }

    private byte[] getMessage(byte[] decodedAuthData, byte[] clientDataHash) {
        return ByteBuffer.allocate(decodedAuthData.length + clientDataHash.length)
                .put(decodedAuthData)
                .put(clientDataHash)
                .array();
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

    public boolean assertPublicKeyCredential(AuthenticationPublicKeyCredential credential) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, SignatureException {
        log.info("=== assertion start ===");
        byte[] authData = decodeBase64(credential.getAuthenticatorData());
        String userId = new String(decodeBase64(credential.getUserHandle()));

        PublicKeySource publicKeySource = keySourceRepository.findByUserId(userId).orElseThrow(() -> new RuntimeException("존재하지 않는 사용자"));
        byte[] clientDataHash = hash(credential.getClientDataJSON());
        byte[] message = getMessage(authData, clientDataHash);
        String keyType = publicKeySource.getKeyType();
        PublicKey publicKey = getPublicKey(publicKeySource);
        Signature signature = null;
        if(keyType.equals("EC")) {
            signature = getECSignature(publicKeySource);
        } else if(keyType.equals("RSA")) {
            signature = getRSASignature(publicKeySource);
        }
        signature.initVerify(publicKey);
        signature.update(message);
        boolean verify = signature.verify(decodeBase64(credential.getSignature()));
        if (verify) {
            log.info("=== assertion success ===");
        }
        return true;
    }
}
