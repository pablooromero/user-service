package com.user_service.user_service.services;

import com.user_service.user_service.dtos.*;
import com.user_service.user_service.models.UserEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

public interface UserService {
    UserEntity saveUser(UserEntity user);

    ResponseEntity<Long> getUserIdByEmail(String email);

    RegisterUserRequest getUserByEmail(String email);

    ResponseEntity<UserDTO> updateUser(Long id, UpdateUserRequest updateUser);

    void deleteUserById(Long id);

    UserEntity findByEmail(String email);

    AuthDTO changePassword(ChangePasswordRequest changePasswordRequest, Authentication authentication);
}
