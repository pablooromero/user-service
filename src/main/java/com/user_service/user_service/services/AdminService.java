package com.user_service.user_service.services;

import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.exceptions.IllegalAttributeException;
import com.user_service.user_service.models.UserEntity;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface AdminService {
    UserEntity saveUser(UserEntity user);

    ResponseEntity<List<UserEntity>> getAllUsers();

    ResponseEntity<UserDTO> createUser(UserDTO userDTO) throws IllegalAttributeException;

    ResponseEntity<UserDTO> createAdmin(UserDTO userDTO) throws IllegalAttributeException;

    void validateUser(UserDTO userDTO) throws IllegalAttributeException;
}
