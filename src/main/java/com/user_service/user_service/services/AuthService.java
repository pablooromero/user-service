package com.user_service.user_service.services;

import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.LoginUserDTO;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.exceptions.UserException;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity<String> loginUser(LoginUserDTO loginUserDTO) throws UserException;

    UserDTO createUser(CreateUserRequest newUser) throws UserException;
}
