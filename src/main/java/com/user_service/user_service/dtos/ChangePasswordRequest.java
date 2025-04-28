package com.user_service.user_service.dtos;

public record ChangePasswordRequest (String currentPassword, String newPassword) {}
