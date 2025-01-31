package com.user_service.user_service.services;

import com.user_service.user_service.dtos.*;
import com.user_service.user_service.exceptions.IllegalAttributeException;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.exceptions.UserNotFoundException;
import com.user_service.user_service.models.UserEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

public interface UserService {
    ResponseEntity<Long> getUserIdByEmail(String email) throws UserNotFoundException;

    UserRegistrationRecord getUserByEmail(String email) throws UserException;

    UserEntity saveUser(UserEntity user);

    ResponseEntity<UserRecord> updateUser(Long id, UpdateUserRecord updateUserRecord) throws UserException;

    void deleteUserById(Long id) throws UserException;

    AuthResponseDTO changePassword(ChangePasswordDTO changePasswordDTO, Authentication authentication) throws UserNotFoundException;

//    ResponseEntity<Long> getUserIdByEmail(String email) throws UserNotFoundException;
//
//    UserDTO getUserByEmail(String email) throws UserNotFoundException;
//
//    UserEntity saveUser(UserEntity user);
//
//    void updateUser(String email, UserDTO userDTO) throws UserNotFoundException, IllegalAttributeException;
//
//    void deleteUserById(Long id) throws UserNotFoundException;
//
//    AuthResponseDTO changePassword(ChangePasswordDTO changePasswordDTO, Authentication authentication) throws UserNotFoundException;
//
//    void validateUser(UserDTO userDTO) throws IllegalAttributeException;
}
