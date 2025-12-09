package com.proyecto.auth.user;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public void eliminarUsuario(Long id){
        if(!userRepository.findById(id).isPresent()){
            throw new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "No existe un usuario con id: "+id
            );
        }
        userRepository.deleteById(id);
    }
}
