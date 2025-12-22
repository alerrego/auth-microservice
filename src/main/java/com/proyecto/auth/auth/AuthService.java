package com.proyecto.auth.auth;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.proyecto.auth.auth.dto.AuthResponse;
import com.proyecto.auth.auth.dto.LoginRequest;
import com.proyecto.auth.auth.dto.RegistroRequest;
import com.proyecto.auth.jwt.JwtService;
import com.proyecto.auth.user.Role;
import com.proyecto.auth.user.User;
import com.proyecto.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse registro(@Valid RegistroRequest request){
        if(userRepository.findByUsername(request.getUsername()).isPresent()){
            throw new ResponseStatusException(
                HttpStatus.CONFLICT,
                "El nombre de usuario ya esta registrado."
            );
        }
        if(userRepository.findByEmail(request.getEmail()).isPresent()){
            throw new ResponseStatusException(
                HttpStatus.CONFLICT,
                "El email ya esta registrado."
            );
        }
        
        User user = User.builder()
            .username(request.getUsername())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .nombre(request.getNombre())
            .apellido(request.getApellido())
            .pais(request.getPais())
            .role(Role.USER)
            .build();

        userRepository.save(user);

        return AuthResponse.builder()
            .token(jwtService.getToken(user))
            .build();
    }

    public AuthResponse login(@Valid LoginRequest request){
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,"Usuario o contraseña incorrectos."
            );
        }
        User user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Usuario o contraseña incorrectos."));
        return AuthResponse.builder()
            .token(jwtService.getToken(user))
            .build();
    }
}
