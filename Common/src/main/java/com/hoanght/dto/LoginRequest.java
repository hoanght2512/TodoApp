package com.hoanght.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

@Getter
@Setter
public class LoginRequest {
    @NotNull(message = "Username is cannot be null")
    @Length(min = 3, max = 30, message = "Username must be between 3 and 30 characters")
    @JsonProperty("username")
    private String username;
    @NotNull(message = "Password is cannot be null")
    @Length(min = 7, max = 30, message = "Password must be between 7 and 30 characters")
    private String password;
}
