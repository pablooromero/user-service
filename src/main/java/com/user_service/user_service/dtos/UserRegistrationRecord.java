package com.user_service.user_service.dtos;

import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.Status;

public record UserRegistrationRecord(Long id, String username, String email, RoleType role, Status userStatus) {
}
