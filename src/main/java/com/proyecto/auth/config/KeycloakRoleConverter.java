package com.proyecto.auth.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // 1. Buscamos la cajita "realm_access" dentro del token
        Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");

        // Si no existe o no tiene roles, devolvemos una lista vacía
        if (realmAccess == null || !realmAccess.containsKey("roles")) {
            return List.of();
        }

        // 2. Extraemos la lista de roles
        Collection<String> roles = (Collection<String>) realmAccess.get("roles");

        // 3. Le agregamos el prefijo "ROLE_" que Spring Security exige por defecto
        return roles.stream()
                .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName))
                .collect(Collectors.toList());
    }
}
