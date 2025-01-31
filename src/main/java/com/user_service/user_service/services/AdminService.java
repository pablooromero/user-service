package com.user_service.user_service.services;

import com.user_service.user_service.dtos.NewUserRecord;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.dtos.UserRecord;
import com.user_service.user_service.exceptions.IllegalAttributeException;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

public interface AdminService {

    UserEntity saveUser(UserEntity user);

    ResponseEntity<Set<UserRecord>> getAllUsers();

    @Transactional(rollbackFor = {Exception.class})
    void validateUser(Long id) throws UserException;

    ResponseEntity<UserRecord> getUserById(Long id) throws UserException;

    @Transactional(rollbackFor = {UserException.class})
    ResponseEntity<UserRecord> createAdmin(NewUserRecord newUserRecord) throws UserException;

    ResponseEntity<String> deleteUserById(Long id) throws UserException;

    boolean existUserById(Long id) throws UserException;

    boolean existUserByEmail(String email) throws UserException;

    void validateUsername(String username) throws UserException;

    void validatePassword(String password) throws UserException;

    void validateEmail(String email) throws UserException;
}
