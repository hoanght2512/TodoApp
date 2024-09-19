package com.hoanght.service.authentication;

import com.hoanght.dto.AuthResponse;
import com.hoanght.dto.LoginRequest;
import com.hoanght.dto.RegistrationRequest;
import com.hoanght.entity.Role;
import com.hoanght.entity.User;
import com.hoanght.entity.UserDetailsImpl;
import com.hoanght.repository.UserRepository;
import com.hoanght.service.jwt.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final JwtUtils jwtUtils;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetailsImpl = (UserDetailsImpl) authentication.getPrincipal();

        String accessToken = jwtUtils.generateAccessToken(userDetailsImpl.getUsername());
        String refreshToken = jwtUtils.generateRefreshToken(userDetailsImpl.getUsername());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .roles(userDetailsImpl.getAuthorities().stream().map(Role::getName).toList())
                .build();
    }

    public boolean register(RegistrationRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return false;
        }

        User register = User.builder()
                .fullname(request.getFullname())
                .username(request.getUsername())
                .password(bCryptPasswordEncoder.encode(request.getPassword()))
                .isEnable(true).build();

        userRepository.save(register);
        return true;
    }

    public AuthResponse refreshToken(HttpServletRequest request) {
        String token = jwtUtils.getToken(request);
        String username = jwtUtils.getUsernameFromToken(token);

        if (!jwtUtils.validateRefreshToken(token))
            throw new BadCredentialsException("Invalid refresh token");

        String accessToken = jwtUtils.generateAccessToken(username);
        String refreshToken = jwtUtils.generateRefreshToken(username);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .build();
    }

    public AuthResponse profile(UserDetailsImpl userDetailsImpl) {
        return AuthResponse.builder()
                .accessToken(jwtUtils.generateAccessToken(userDetailsImpl.getUsername()))
                .refreshToken(jwtUtils.generateRefreshToken(userDetailsImpl.getUsername()))
                .tokenType("Bearer")
                .roles(userDetailsImpl.getAuthorities().stream().map(Role::getName).toList())
                .build();
    }

    public void logout(HttpServletRequest request) {
        String token = jwtUtils.getToken(request);
        jwtUtils.deleteRefreshToken(token);
    }
}
