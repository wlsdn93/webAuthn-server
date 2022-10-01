package com.practice.fido.webAuthn.controller;

import com.practice.fido.webAuthn.dto.EnrollRequestDto;
import com.practice.fido.webAuthn.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
@RequestMapping("/api/user/")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public String enroll(@RequestBody EnrollRequestDto enrollRequestDto) {
        log.info("request from {}", enrollRequestDto.getUsername());
        return userService.enroll(enrollRequestDto);
    }

}
