package com.proyecto.auth.auth;

import java.util.Collections;
import java.util.List;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import jakarta.ws.rs.core.Response;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final Keycloak keycloakAdmin;
    private final RestClient restClient;

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

    public boolean registrarUsuario(String username, String email, String password) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setEnabled(true);
        user.setEmailVerified(false); // Para que tenga que validarlo

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);

        user.setCredentials(Collections.singletonList(credential));

        // Le pedimos a Keycloak que cree el usuario
        try (Response response = keycloakAdmin.realm(realm).users().create(user)) {
            if (response.getStatus() == 201) {
                // OPCIONAL: Mandar el mail de verificación automáticamente
                String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                keycloakAdmin.realm(realm).users().get(userId).executeActionsEmail(List.of("VERIFY_EMAIL"));
                return true;
            }
            return false;
        }
    }

    public boolean recuperarPassword(String email) {
        // Buscamos si existe el usuario por su email
        List<UserRepresentation> users = keycloakAdmin.realm(realm).users().searchByEmail(email, true);
        
        if (!users.isEmpty()) {
            String userId = users.get(0).getId();
            // Le decimos a Keycloak que le mande el mail de reseteo
            keycloakAdmin.realm(realm).users().get(userId).executeActionsEmail(List.of("UPDATE_PASSWORD"));
            return true;
        }
        return false;
    }
}
