package com.hoanght.config;

import com.hoanght.common.RoleName;
import com.hoanght.entity.Role;
import com.hoanght.entity.User;
import com.hoanght.repository.RoleRepository;
import com.hoanght.repository.UserRepository;
import com.hoanght.service.authentication.UserDetailService;
import com.hoanght.service.jwt.AuthEntryPointJwt;
import com.hoanght.service.jwt.JwtTokenFilter;
import com.hoanght.service.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfiguration {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);
    private final JwtUtils jwtUtils;
    private final AuthEntryPointJwt unauthorizedHandler;
    private final UserDetailService userDetailService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(PasswordEncoder passwordEncoder,
                                                       UserDetailService userDetailService) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        authenticationProvider.setUserDetailsService(userDetailService);
        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public JwtTokenFilter jwtAuthenticationFilter() {
        return new JwtTokenFilter(jwtUtils, userDetailService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.cors(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(
                request -> request.requestMatchers("/api/auth/**").permitAll().requestMatchers("/api/admin/**").hasRole(
                        "ADMIN").requestMatchers("/api/user/**").hasAnyRole("USER",
                                                                            "ADMIN").anyRequest().authenticated());
        http.exceptionHandling(e -> e.authenticationEntryPoint(unauthorizedHandler));
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public CommandLineRunner initData(UserRepository userRepository, RoleRepository roleRepository) {
        return args -> {
            Role userRole = roleRepository.findByName(RoleName.ROLE_USER).orElseGet(
                    () -> roleRepository.save(new Role(RoleName.ROLE_USER)));
            Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN).orElseGet(
                    () -> roleRepository.save(new Role(RoleName.ROLE_ADMIN)));

            if (!userRepository.existsByUsername("admin")) {
                userRepository.save(
                        User.builder()
                                .fullname("Administator")
                                .username("admin")
                                .password(bCryptPasswordEncoder().encode("123456"))
                                .isEnable(true)
                                .roles(Set.of(userRole, adminRole)).build());
            }
        };
    }
}
