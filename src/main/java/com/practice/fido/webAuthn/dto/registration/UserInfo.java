package com.practice.fido.webAuthn.dto.registration;

import lombok.Getter;

@Getter
public class UserInfo {
    private String id;
    private String name;
    private String displayName;

    public UserInfo(String id, String name, String displayName) {
        this.id = id;
        this.name = name;
        this.displayName = displayName;
    }
}
