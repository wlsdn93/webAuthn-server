package com.practice.fido.webAuthn.dto;

import lombok.Getter;

@Getter
public class EnrollRequestDto {
    private String username;
    private String password;
    private String displayName;
}
