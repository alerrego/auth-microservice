package com.proyecto.auth.auth;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import com.proyecto.auth.auth.dto.RegistroRequest;
import com.proyecto.auth.auth.dto.StaffRequest;
import com.proyecto.auth.email.EmailService;
import com.proyecto.auth.verificationToken.VerificacionToken;
import com.proyecto.auth.verificationToken.VerificacionTokenRepository;

import jakarta.transaction.Transactional;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final Keycloak keycloakAdmin;
    private final RestClient restClient;
    private final VerificacionTokenRepository verificationTokenRepository;
    private final EmailService emailService;

    @Value("${keycloak.server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    public String login(String username, String password) {
        String tokenEndpoint = serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", clientId);
        formData.add("grant_type", "password");
        formData.add("username", username);
        formData.add("password", password);
        formData.add("client_secret", clientSecret);

        // Hacemos el POST directo a Keycloak y devolvemos el JSON con el token
        return restClient.post()
                .uri(tokenEndpoint)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formData)
                .retrieve()
                .body(String.class);
    }

    @Transactional
    public boolean registrarUsuario(RegistroRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEnabled(false);
        user.setEmailVerified(false); // Para que tenga que validarlo

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(request.password());
        credential.setTemporary(false);

        user.setCredentials(Collections.singletonList(credential));

        // Le pedimos a Keycloak que cree el usuario
        try (Response response = keycloakAdmin.realm(realm).users().create(user)) {
            if (response.getStatus() == 201) {
                String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                
                //CREAMOS EL TOKEN DE VERIFICACION QUE SE LE VA A ENVIAR POR MAIL
                String tokenRandom = UUID.randomUUID().toString();
                VerificacionToken vToken = new VerificacionToken();
                vToken.setToken(tokenRandom);
                vToken.setKeycloakUserId(userId);
                vToken.setFechaExpiracion(LocalDateTime.now().plusHours(12));
                vToken.setTipo("REGISTRO");
                verificationTokenRepository.save(vToken);

                emailService.enviarEmailConfirmacion(request.email(), tokenRandom);

                return true;
            }
            return false;
        }
    }

    @Transactional
    public void confirmarCuenta(String token) {
        // 1. Buscamos el token en nuestra BD
        VerificacionToken vToken = verificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("El token es inválido o no existe."));

        if (!vToken.getTipo().equals("REGISTRO")) {
            throw new IllegalArgumentException("El token no es válido para esta acción.");
        }
        // 2. Validaciones de seguridad
        if (vToken.isUsado()) {
            throw new IllegalStateException("Esta cuenta ya fue verificada.");
        }
        if (vToken.getFechaExpiracion().isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("El link ha expirado. Deberás solicitar uno nuevo.");
        }

        String userId = vToken.getKeycloakUserId();
        var userResource = keycloakAdmin.realm(realm).users().get(userId);
        UserRepresentation user = userResource.toRepresentation();

        user.setEnabled(true);
        user.setEmailVerified(true);
        userResource.update(user);

        vToken.setUsado(true);
        verificationTokenRepository.save(vToken);
    }

    //REENVIAR USANDO EL TOKEN VIEJO (Para la pantalla de /confirmar)
    @Transactional
    public void reenviarPorTokenVencido(String tokenViejo) {
        VerificacionToken anterior = verificationTokenRepository.findByToken(tokenViejo)
                .orElseThrow(() -> new IllegalArgumentException("Token original no encontrado."));

        String userId = anterior.getKeycloakUserId();
        UserRepresentation user = keycloakAdmin.realm(realm).users().get(userId).toRepresentation();

        generarYEnviarNuevoToken(user.getId(), user.getEmail());
    }

    //REENVIAR USANDO EL EMAIL (Para el rebote del Login) ES IDENTIFICADOR EL CAMPO PQ PODRIA SER QUE HAYA HECHO EL LOGIN CON EL USERNAME
    @Transactional
    public void reenviarPorEmail(String identificador) {
        var users = keycloakAdmin.realm(realm).users().search(identificador);
        if (users.isEmpty()) throw new IllegalArgumentException("Usuario no encontrado.");
        
        UserRepresentation user = users.get(0);
        if (user.isEmailVerified()) throw new IllegalStateException("La cuenta ya está activa.");

        generarYEnviarNuevoToken(user.getId(), user.getEmail());
    }

    // Método privado auxiliar para no repetir código
    private void generarYEnviarNuevoToken(String userId, String email) {
        String nuevoToken = UUID.randomUUID().toString();
        VerificacionToken vToken = new VerificacionToken();
        vToken.setToken(nuevoToken);
        vToken.setKeycloakUserId(userId);
        vToken.setFechaExpiracion(LocalDateTime.now().plusHours(24));
        vToken.setTipo("REGISTRO");
        vToken.setUsado(false);

        verificationTokenRepository.save(vToken);
        emailService.enviarEmailConfirmacion(email, nuevoToken);
    }

    public boolean registrarOrganizador(RegistroRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEnabled(true);
        user.setEmailVerified(true);

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(request.password());
        credential.setTemporary(false);
        user.setCredentials(Collections.singletonList(credential));

        // Le pedimos a Keycloak que cree el usuario
        try (Response response = keycloakAdmin.realm(realm).users().create(user)) {
            if (response.getStatus() == 201) {
                // Extraemos el ID del usuario creado desde el header 'Location'
                String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                RoleRepresentation roleOrganizador = keycloakAdmin.realm(realm)
                    .roles()
                    .get("organizador") // Asegurate que el nombre coincida exacto en Keycloak
                    .toRepresentation();
                keycloakAdmin.realm(realm).users().get(userId).roles().realmLevel().add(List.of(roleOrganizador));

                // 2. QUITAR ROL 'user' (que se asignó automáticamente por ser Default Role)
                RoleRepresentation roleUser = keycloakAdmin.realm(realm)
                    .roles()
                    .get("user") // Asegurate que el nombre sea exacto
                    .toRepresentation();
                keycloakAdmin.realm(realm).users().get(userId).roles().realmLevel().remove(List.of(roleUser));
                
                    return true;
            }
            return false;
        }
    }

    @Transactional
    public void solicitarRecuperacionPassword(String email) {
        // Buscamos al usuario en Keycloak por email
        var users = keycloakAdmin.realm(realm).users().searchByEmail(email, true);
        
        // Por seguridad, si el mail no existe no tiramos error para evitar ataques de enumeración
        if (users == null || users.isEmpty()) {
            return; 
        }
        
        String userId = users.get(0).getId();

        // Generamos el token de recuperación
        String tokenRandom = UUID.randomUUID().toString();
        VerificacionToken vToken = new VerificacionToken();
        vToken.setToken(tokenRandom);
        vToken.setKeycloakUserId(userId);
        vToken.setFechaExpiracion(LocalDateTime.now().plusHours(2)); // Los de password expiran más rápido
        vToken.setTipo("RECUPERACION");
        vToken.setUsado(false);
        
        verificationTokenRepository.save(vToken);
        emailService.enviarEmailRecuperacion(email, tokenRandom);
    }

    @Transactional
    public void restablecerPassword(String token, String nuevaPassword) {
        VerificacionToken vToken = verificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Token inválido o inexistente."));

        if (!vToken.getTipo().equals("RECUPERACION")) {
            throw new IllegalArgumentException("El token no es válido para esta acción.");
        }
        if (vToken.isUsado() || vToken.getFechaExpiracion().isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("El enlace ha expirado o ya fue utilizado.");
        }

        // Le pisamos la contraseña en Keycloak
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(nuevaPassword);
        cred.setTemporary(false);

        keycloakAdmin.realm(realm).users().get(vToken.getKeycloakUserId()).resetPassword(cred);

        // Quemamos el token
        vToken.setUsado(true);
        verificationTokenRepository.save(vToken);
    }

    public Optional<Map<String, Object>> buscarUsuarioPorEmail(String email) {
        // Buscamos en Keycloak con "true" para coincidencia exacta
        List<UserRepresentation> usuarios = keycloakAdmin.realm(realm)
                .users()
                .search(email, true);

        if (usuarios.isEmpty()) {
            return Optional.empty(); // No existe
        }

        UserRepresentation u = usuarios.get(0);
        
        // Mapeamos los datos limpios para el frontend
        Map<String, Object> datosUsuario = Map.of(
            "id", u.getId(),
            "nombre", u.getFirstName(),
            "apellido", u.getLastName(),
            "email", u.getEmail(),
            "username", u.getUsername(),
            "existe", true
        );

        return Optional.of(datosUsuario);
    }

    public String gestionarUsuarioStaff(StaffRequest request) {

        String userId;

        UserRepresentation nuevoUsuario = new UserRepresentation();
        nuevoUsuario.setUsername(request.username());
        nuevoUsuario.setEmail(request.email());
        nuevoUsuario.setFirstName(request.nombre());
        nuevoUsuario.setLastName(request.apellido());
        nuevoUsuario.setEnabled(true);
        nuevoUsuario.setEmailVerified(true);

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setTemporary(false);
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue("1234"); // Contraseña por defecto que le va a pasar el organizador

        nuevoUsuario.setCredentials(Collections.singletonList(credential));

        Response response = keycloakAdmin.realm(realm).users().create(nuevoUsuario);

        if (response.getStatus() == 201) {
            // Keycloak devuelve el ID en la URL de creación, lo extraemos así:
            String path = response.getLocation().getPath();
            userId = path.substring(path.lastIndexOf('/') + 1);
        } else {
            throw new RuntimeException("Fallo al crear el usuario en Keycloak. Código HTTP: " + response.getStatus());
        }

        asignarRolEnKeycloak(userId, request.rol());
        return userId;
    }

    private void asignarRolEnKeycloak(String userId, String nombreRol) {
        try {
            // Buscamos el rol en el Realm
            RoleRepresentation realmRole = keycloakAdmin.realm(realm)
                    .roles()
                    .get(nombreRol)
                    .toRepresentation();

            // Apuntamos al usuario específico
            UserResource userResource = keycloakAdmin.realm(realm).users().get(userId);

            // Obtenemos los roles que ya tiene para no asignarlo dos veces
            List<RoleRepresentation> rolesActuales = userResource.roles().realmLevel().listAll();
            
            boolean yaTieneElRol = rolesActuales.stream()
                    .anyMatch(r -> r.getName().equals(nombreRol));

            if (!yaTieneElRol) {
                userResource.roles().realmLevel().add(Collections.singletonList(realmRole));
            }

        } catch (Exception e) {
            System.err.println("Advertencia: No se pudo asignar el rol en Keycloak: " + e.getMessage());
        }
    }
}
