package com.hoanght.service.authentication;

import com.hoanght.common.RoleName;
import com.hoanght.dto.AuthResponse;
import com.hoanght.dto.LoginRequest;
import com.hoanght.dto.RegistrationRequest;
import com.hoanght.entity.Person;
import com.hoanght.entity.Role;
import com.hoanght.entity.User;
import com.hoanght.repository.RoleRepository;
import com.hoanght.repository.UserRepository;
import com.hoanght.service.jwt.JwtUtils;
import jakarta.annotation.PostConstruct;
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

import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final JwtUtils jwtUtils;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsernameOrEmail(), request.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();

        String accessToken = jwtUtils.generateAccessToken(user.getUsername());
        String refreshToken = jwtUtils.generateRefreshToken(user.getUsername());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .roles(user.getAuthorities().stream().map(Role::getName).toList())
                .build();
    }

    public boolean register(RegistrationRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return false;
        }

        Person register = Person.builder()
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

    public void logout(HttpServletRequest request) {
        String token = jwtUtils.getToken(request);
        jwtUtils.deleteRefreshToken(token);
    }

    public AuthResponse profile(User user) {
        return AuthResponse.builder()
                .accessToken(jwtUtils.generateAccessToken(user.getUsername()))
                .refreshToken(jwtUtils.generateRefreshToken(user.getUsername()))
                .tokenType("Bearer")
                .roles(user.getAuthorities().stream().map(Role::getName).toList())
                .build();
    }

    @PostConstruct
    public void init() {
        if (!roleRepository.existsByName(RoleName.ROLE_ADMIN)) {
            roleRepository.save(Role.builder().name(RoleName.ROLE_ADMIN).build());
        }

        if (!roleRepository.existsByName(RoleName.ROLE_USER)) {
            roleRepository.save(Role.builder().name(RoleName.ROLE_USER).build());
        }

        if (!userRepository.existsByUsername("admin")) {
            Person admin = Person.builder()
                    .username("admin")
                    .password(bCryptPasswordEncoder.encode("admin123"))
                    .fullname("Admin")
                    .isEnable(true).build();

            Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Role not found"));
            Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Role not found"));

            admin.setRoles(Set.of(adminRole, userRole));
            userRepository.save(admin);
        }
    }
}
