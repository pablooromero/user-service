package com.user_service.user_service.services;

import com.user_service.user_service.dtos.*;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

public interface UserService {
    UserEntity saveUser(UserEntity user);

    ResponseEntity<Long> getUserIdByEmail(String email) throws UserException;

    RegisterUserRequest getUserByEmail(String email) throws UserException;

    ResponseEntity<UserDTO> updateUser(Long id, UpdateUserRequest updateUser) throws UserException;

    void deleteUserById(Long id) throws UserException;

    AuthDTO changePassword(ChangePasswordRequest changePasswordRequest, Authentication authentication) throws UserException;
}
