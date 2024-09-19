package com.hoanght.controller;

import com.hoanght.dto.AuthResponse;
import com.hoanght.dto.LoginRequest;
import com.hoanght.dto.RegistrationRequest;
import com.hoanght.entity.RefreshToken;
import com.hoanght.entity.UserDetailsImpl;
import com.hoanght.service.authentication.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        AuthResponse auth = authenticationService.login(request);
        return ResponseEntity.ok(auth);
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody RegistrationRequest request) {
        boolean result = authenticationService.register(request);
        if (result) {
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.badRequest().build();
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(HttpServletRequest request) {
        AuthResponse authResponse = authenticationService.refreshToken(request);
        return ResponseEntity.ok(authResponse);
    }

    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    @GetMapping("/me")
    public ResponseEntity<AuthResponse> profile(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        AuthResponse authResponse = authenticationService.profile(userDetails);
        return ResponseEntity.ok(authResponse);
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        authenticationService.logout(request);
        return ResponseEntity.ok().build();
    }
}
