package com.user_service.user_service.services;

import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.models.UserEntity;
import org.springframework.http.ResponseEntity;

import java.util.Set;

public interface AdminService {
    UserEntity saveUser(UserEntity user);

    ResponseEntity<Set<UserDTO>> getAllUsers();

    void validateUser(Long id);

    ResponseEntity<UserDTO> getUserById(Long id);

    ResponseEntity<UserDTO> createAdmin(CreateUserRequest newUser);

    ResponseEntity<String> deleteUserById(Long id);

    boolean existUserById(Long id);

    void validatePassword(String password);

    void validateEmail(String email);

    boolean existUserByEmail(String email);
}
