package com.user_service.user_service.dtos;

public record WelcomeMessage(
        String username,
        String email,
        String token
) {
}
