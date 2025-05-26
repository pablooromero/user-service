package com.user_service.user_service.services;

import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.LoginUserDTO;
import com.user_service.user_service.dtos.UserDTO;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity<String> loginUser(LoginUserDTO loginUserDTO);

    UserDTO createUser(CreateUserRequest newUser);
}
