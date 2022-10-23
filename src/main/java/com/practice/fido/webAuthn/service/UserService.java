package com.practice.fido.webAuthn.service;

import com.practice.fido.webAuthn.dto.EnrollRequestDto;
import com.practice.fido.webAuthn.entity.User;
import com.practice.fido.webAuthn.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
@Slf4j
@Transactional
public class UserService {

    @Value("${secret}")
    private String secret;
    private static final SecureRandom random = new SecureRandom();
    private static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public String enroll(EnrollRequestDto enrollRequestDto) {
        log.info("=== enroll request ===");
        String username = enrollRequestDto.getUsername();
        log.info("username : {}", username);
        String password = enrollRequestDto.getPassword();
        String displayName = enrollRequestDto.getDisplayName();
        String userId = getUserId();
        String hashedPassword = getHashedPassword(password);
        User user = new User(userId, username, hashedPassword, displayName);
        return userRepository.save(user).getId();
    }

    private String getUserId() {
        byte[] buffer = new byte[16];
        random.nextBytes(buffer);
        return encoder.encodeToString(buffer);
    }

    private String getHashedPassword(String pwd)  {
        try {
            MessageDigest digester = MessageDigest.getInstance("SHA-256");
            byte[] hash = digester.digest(pwd.getBytes("UTF-8"));
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) {
                    sb.append('0');
                }
                sb.append(hex);
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
