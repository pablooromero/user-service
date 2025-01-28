package com.user_service.user_service.services;

import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.exceptions.IllegalAttributeException;
import com.user_service.user_service.exceptions.UserNotFoundException;
import com.user_service.user_service.models.UserEntity;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface UserService {

    ResponseEntity<Long> getUserByEmail(String email) throws UserNotFoundException;

    UserEntity saveUser(UserEntity user);

    //TODO Refactor para hacer solo poder editar/borrar su propio usuario
    ResponseEntity<UserDTO> updateUser(UserDTO userDTO) throws UserNotFoundException, IllegalAttributeException;

    ResponseEntity<String> deleteUser(Long id) throws UserNotFoundException;

    void validateUser(UserDTO userDTO) throws IllegalAttributeException;
}
