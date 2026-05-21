package com.proyecto.auth.auth.dto;

public record RestablecerPasswordRequest(String token, String nuevaPassword) {}