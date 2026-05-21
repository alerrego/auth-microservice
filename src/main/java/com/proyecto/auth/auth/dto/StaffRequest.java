package com.proyecto.auth.auth.dto;

public record StaffRequest(
    String rol, 
    String username,
    String email,
    String nombre,
    String apellido
) {}