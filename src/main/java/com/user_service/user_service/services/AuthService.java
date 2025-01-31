package com.user_service.user_service.services;

import com.user_service.user_service.dtos.*;
import com.user_service.user_service.exceptions.UserException;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;

public interface AuthService {

    ResponseEntity<String> loginUser(LoginUserRecord loginUserRecord) throws UserException;

    @Transactional(rollbackFor = {UserException.class})
    UserRecord createUser(NewUserRecord newUserRecord) throws UserException;
}
