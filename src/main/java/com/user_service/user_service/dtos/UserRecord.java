package com.user_service.user_service.dtos;

import com.user_service.user_service.enums.RoleType;

public record UserRecord(Long id, String username, String email, RoleType role) {
}
