package com.suriya.jwtWithRolesandClaims.controller;

import com.suriya.jwtWithRolesandClaims.dto.LoginDto;
import com.suriya.jwtWithRolesandClaims.dto.RegisterDto;
import com.suriya.jwtWithRolesandClaims.service.AuthService;
import com.suriya.jwtWithRolesandClaims.utils.JWTUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuthController {

    private final JWTUtils jwtUtils;
    private final AuthService authService;

    AuthController(JWTUtils jwtUtils,AuthService authService){
        this.authService = authService;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto){
        return authService.registerUser(registerDto);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto loginDto){
        return authService.login(loginDto);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String,String> rbody){
        String token = rbody.get("refreshToken");
        return this.authService.validateRefreshToken(token);
    }

}
