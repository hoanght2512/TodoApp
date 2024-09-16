package com.hoanght.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.hoanght.common.RoleName;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
public class AuthResponse {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("token_type")
    private String tokenType;
    @JsonProperty("refresh_token")
    private String refreshToken;
    @JsonProperty("roles")
    private List<RoleName> roles;
}
