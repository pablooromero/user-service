package com.user_service.user_service.dtos;

public record CreateUserRequest(String name, String lastName, String email, String password) {
}
