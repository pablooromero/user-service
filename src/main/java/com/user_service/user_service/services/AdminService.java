package com.user_service.user_service.services;

import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import org.springframework.http.ResponseEntity;

import java.util.Set;

public interface AdminService {
    UserEntity saveUser(UserEntity user);

    ResponseEntity<Set<UserDTO>> getAllUsers();

    void validateUser(Long id) throws UserException;

    ResponseEntity<UserDTO> getUserById(Long id) throws UserException;

    ResponseEntity<UserDTO> createAdmin(CreateUserRequest newUser) throws UserException;

    ResponseEntity<String> deleteUserById(Long id) throws UserException;

    boolean existUserById(Long id) throws UserException;

    void validatePassword(String password) throws UserException;

    void validateEmail(String email) throws UserException;

    boolean existUserByEmail(String email) throws UserException;
}
