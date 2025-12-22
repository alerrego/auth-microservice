package com.proyecto.auth.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
    @NotBlank(message = "El nombre de usuario no puede estar vacío")
    private String username;
    @NotBlank(message = "La contraseña del usuario no puede estar vacío")
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    private String password;
}
