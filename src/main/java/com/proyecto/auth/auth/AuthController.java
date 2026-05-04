package com.proyecto.auth.auth;

import java.util.Map; // Ajustá este import según tu paquete

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.proyecto.auth.auth.dto.LoginRequest;
import com.proyecto.auth.auth.dto.RecuperarPasswordRequest;
import com.proyecto.auth.auth.dto.RegistroRequest;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // --- 1. ENDPOINT DE LOGIN ---
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            String tokenResponse = authService.login(request.username(), request.password());
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            System.err.println("Error en login: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Usuario o contraseña incorrectos"));
        }
    }

    @PostMapping("/registro")
    public ResponseEntity<?> registrar(@RequestBody RegistroRequest request) {
        try {
            boolean creado = authService.registrarUsuario(
                    request.username(),
                    request.email(),
                    request.password()
            );

            if (creado) {
                return ResponseEntity.status(HttpStatus.CREATED)
                        .body(Map.of("mensaje", "Cuenta creada exitosamente. Revisa tu email."));
            } else {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(Map.of("error", "No se pudo crear la cuenta."));
            }
        } catch (Exception e) {
            System.err.println("Error al registrar: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "El usuario o email ya están en uso"));
        }
    }

    @PostMapping("/recuperar-password")
    public ResponseEntity<?> recuperarPassword(@RequestBody RecuperarPasswordRequest request) {
        try {
            authService.recuperarPassword(request.email());
            return ResponseEntity.ok(Map.of("mensaje", "Si el correo existe en nuestro sistema, te enviamos las instrucciones."));
        } catch (Exception e) {
            System.err.println("Error al recuperar password: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Hubo un problema al procesar la solicitud."));
        }
    }
}
