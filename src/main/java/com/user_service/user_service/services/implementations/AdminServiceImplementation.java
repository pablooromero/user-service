package com.user_service.user_service.services.implementations;


import com.user_service.user_service.dtos.NewUserRecord;
import com.user_service.user_service.dtos.UserRecord;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.Status;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.utils.Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AdminServiceImplementation implements AdminService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Override
    public UserEntity saveUser(UserEntity user) {
        return userRepository.save(user);
    }


    @Override
    public ResponseEntity<Set<UserRecord>> getAllUsers() {
        Set<UserRecord> users = userRepository.findAll()
                .stream()
                .map(user -> new UserRecord(user.getId(), user.getUsername(), user.getEmail(), user.getRole()))
                .collect(Collectors.toSet());

        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @Transactional(rollbackFor = {Exception.class})
    @Override
    public void validateUser(Long id) throws UserException {
        UserEntity user = userRepository.findById(id).orElseThrow(()->new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND));
        user.setStatus(Status.ACTIVE);
        userRepository.save(user);
    }

    @Override
    public ResponseEntity<UserRecord> getUserById(Long id) throws UserException {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(()->new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND));

        return new ResponseEntity<>(new UserRecord(user.getId(), user.getUsername(),user.getEmail(),user.getRole()), HttpStatus.OK);
    }

    @Transactional(rollbackFor = {UserException.class})
    @Override
    public ResponseEntity<UserRecord> createAdmin(NewUserRecord newUserRecord) throws UserException {
        validateUsername(newUserRecord.username());
        validatePassword(newUserRecord.password());
        validateEmail(newUserRecord.email());

        UserEntity userEntity = new UserEntity(newUserRecord.username(), passwordEncoder.encode(newUserRecord.password()), newUserRecord.email(), RoleType.ADMIN);
        userEntity = saveUser(userEntity);

        return new ResponseEntity<>(new UserRecord(userEntity.getId(), userEntity.getUsername(),userEntity.getEmail(),userEntity.getRole()), HttpStatus.CREATED);
    }


    @Override
    public ResponseEntity<String> deleteUserById(Long id) throws UserException {
        if (!existUserById(id)) {
            throw new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
        }else{
            userRepository.deleteById(id);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }

    }

    @Override
    public boolean existUserById(Long id) throws UserException {
        return userRepository.existsById(id);
    }

    @Override
    public boolean existUserByEmail(String email) throws UserException {
        return userRepository.existsByEmail(email);
    }

    @Override
    public void validateUsername(String username) throws UserException {
        if (username == null || username.isBlank()) {
            throw new UserException(Constants.EMPTY_US);
        }
    }

    @Override
    public void validatePassword(String password) throws UserException {
        if (password == null || password.isBlank()) {
            throw new UserException(Constants.EMPTY_PASS);
        }
    }

    @Override
    public void validateEmail(String email) throws UserException {
        if (existUserByEmail(email)) {
            throw new UserException(Constants.EXIST_EMAIL,HttpStatus.CONFLICT);
         }else {
            if (!validMail(email)) {
                throw new UserException(Constants.INV_EMAIL,HttpStatus.CONFLICT);
            }
        }
    }

    public boolean validMail(String email) {
        for (String dom : Constants.URL_MAILS) {
            if (email.endsWith(dom)) {
                return true;
            }
        }
        return false;
    }
}
