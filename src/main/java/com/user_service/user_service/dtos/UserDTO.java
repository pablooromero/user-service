package com.user_service.user_service.dtos;

import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;

public record UserDTO(Long id, String name, String lastName, String email, RoleType role, UserStatus status) {
}
