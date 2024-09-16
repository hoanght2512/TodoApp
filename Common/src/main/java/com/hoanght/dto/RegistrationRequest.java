package com.hoanght.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

@Getter
@Setter
@Builder
public class RegistrationRequest {
    @NotNull(message = "Username is can not be null")
    @Length(min = 6, max = 50, message = "Username must be between 6 and 50 characters")
    private String username;
    @NotNull(message = "Password is can not be null")
    @Length(min = 6, max = 50, message = "Password must be between 6 and 50 characters")
    private String password;
    @NotNull(message = "Fullname is can not be null")
    @Length(min = 6, max = 50, message = "Fullname must be between 6 and 50 characters")
    private String fullname;
}
