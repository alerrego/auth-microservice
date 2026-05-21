package com.proyecto.auth.auth;

import java.util.Map; // Ajustá este import según tu paquete
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.proyecto.auth.auth.dto.EmailRequest;
import com.proyecto.auth.auth.dto.LoginRequest;
import com.proyecto.auth.auth.dto.RecuperarPasswordRequest;
import com.proyecto.auth.auth.dto.RegistroRequest;
import com.proyecto.auth.auth.dto.RestablecerPasswordRequest;
import com.proyecto.auth.auth.dto.StaffRequest;
import com.proyecto.auth.auth.dto.TokenRequest;

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
            boolean creado = authService.registrarUsuario(request);

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

    @GetMapping("/confirmar")
    public ResponseEntity<?> confirmarRegistro(@RequestParam String token) {
        try {
            authService.confirmarCuenta(token);      
            return ResponseEntity.ok("¡Cuenta verificada exitosamente! Ya podés iniciar sesión.");
            
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Ocurrió un error al verificar la cuenta.");
        }
    }

    @PostMapping("/reenviar-por-token")
    public ResponseEntity<?> reenviarPorToken(@RequestBody TokenRequest request) {
        try {
            authService.reenviarPorTokenVencido(request.token());
            return ResponseEntity.ok("Nuevo enlace enviado.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/reenviar-por-email")
    public ResponseEntity<?> reenviarPorEmail(@RequestBody EmailRequest request) {
        try {
            authService.reenviarPorEmail(request.email());
            return ResponseEntity.ok("Nuevo enlace enviado.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/registro-organizador")
    @PreAuthorize("hasAnyRole('admin')")
    public ResponseEntity<?> registrarOrganizador(@RequestBody RegistroRequest request) {
        try {
            boolean creado = authService.registrarOrganizador(request);

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
            authService.solicitarRecuperacionPassword(request.email());
            return ResponseEntity.ok("Si el correo existe, te enviamos las instrucciones.");
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Ocurrió un error.");
        }
    }

    @PostMapping("/restablecer-password")
    public ResponseEntity<?> restablecerPassword(@RequestBody RestablecerPasswordRequest request) {
        try {
            authService.restablecerPassword(request.token(), request.nuevaPassword());
            return ResponseEntity.ok("Contraseña actualizada con éxito.");
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error al cambiar la contraseña.");
        }
    }

    @GetMapping("/usuarios/buscar")
    @PreAuthorize("hasRole('organizador')")
    public ResponseEntity<?> buscarUsuarioPorEmail(@RequestParam String email) {
        
        Optional<Map<String, Object>> usuarioOpt = authService.buscarUsuarioPorEmail(email);

        if (usuarioOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("mensaje", "Usuario no encontrado"));
        }

        // Si lo encuentra, devuelve un 200 OK con el JSON del usuario
        return ResponseEntity.ok(usuarioOpt.get());
    }

    @PostMapping("/staff/gestionar")
    @PreAuthorize("hasRole('organizador')")
    public ResponseEntity<String> gestionarUsuarioStaff(@RequestBody StaffRequest request) {
        try {
            String usuarioId = authService.gestionarUsuarioStaff(request);
            // Devolvemos solo el string con el UUID de Keycloak
            return ResponseEntity.ok(usuarioId);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al gestionar el usuario: " + e.getMessage());
        }
    }
}
