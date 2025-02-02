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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(AdminServiceImplementation.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserEntity saveUser(UserEntity user) {
        logger.info("Saving user: {}", user.getUsername());
        return userRepository.save(user);
    }

    @Override
    public ResponseEntity<Set<UserRecord>> getAllUsers() {
        logger.info("Fetching all users");
        Set<UserRecord> users = userRepository.findAll()
                .stream()
                .map(user -> new UserRecord(user.getId(), user.getUsername(), user.getEmail(), user.getRole()))
                .collect(Collectors.toSet());

        logger.info("Found {} users", users.size());
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @Transactional(rollbackFor = {Exception.class})
    @Override
    public void validateUser(Long id) throws UserException {
        logger.info("Validating user with ID: {}", id);
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.error("User with ID {} not found", id);
                    return new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
                });
        user.setStatus(Status.ACTIVE);
        userRepository.save(user);
        logger.info("User with ID {} has been validated", id);
    }

    @Override
    public ResponseEntity<UserRecord> getUserById(Long id) throws UserException {
        logger.info("Fetching user by ID: {}", id);
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.error("User with ID {} not found", id);
                    return new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
                });

        logger.info("User with ID {} found", id);
        return new ResponseEntity<>(new UserRecord(user.getId(), user.getUsername(), user.getEmail(), user.getRole()), HttpStatus.OK);
    }

    @Transactional(rollbackFor = {UserException.class})
    @Override
    public ResponseEntity<UserRecord> createAdmin(NewUserRecord newUserRecord) throws UserException {
        logger.info("Creating new admin: {}", newUserRecord.username());

        validateUsername(newUserRecord.username());
        validatePassword(newUserRecord.password());
        validateEmail(newUserRecord.email());

        UserEntity userEntity = new UserEntity(newUserRecord.username(), passwordEncoder.encode(newUserRecord.password()), newUserRecord.email(), RoleType.ADMIN);
        userEntity = saveUser(userEntity);

        logger.info("Admin {} created successfully", userEntity.getUsername());
        return new ResponseEntity<>(new UserRecord(userEntity.getId(), userEntity.getUsername(), userEntity.getEmail(), userEntity.getRole()), HttpStatus.CREATED);
    }

    @Override
    public ResponseEntity<String> deleteUserById(Long id) throws UserException {
        logger.info("Deleting user with ID: {}", id);
        if (!existUserById(id)) {
            logger.error("User with ID {} not found", id);
            throw new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
        } else {
            userRepository.deleteById(id);
            logger.info("User with ID {} deleted successfully", id);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
    }

    @Override
    public boolean existUserById(Long id) throws UserException {
        boolean exists = userRepository.existsById(id);
        logger.info("Checking existence of user with ID {}: {}", id, exists);
        return exists;
    }

    @Override
    public boolean existUserByEmail(String email) throws UserException {
        boolean exists = userRepository.existsByEmail(email);
        logger.info("Checking existence of user with email {}: {}", email, exists);
        return exists;
    }

    @Override
    public void validateUsername(String username) throws UserException {
        if (username == null || username.isBlank()) {
            logger.error("Username validation failed: empty username");
            throw new UserException(Constants.EMPTY_US);
        }
    }

    @Override
    public void validatePassword(String password) throws UserException {
        if (password == null || password.isBlank()) {
            logger.error("Password validation failed: empty password");
            throw new UserException(Constants.EMPTY_PASS);
        }
    }

    @Override
    public void validateEmail(String email) throws UserException {
        if (existUserByEmail(email)) {
            logger.error("Email validation failed: email {} already exists", email);
            throw new UserException(Constants.EXIST_EMAIL, HttpStatus.CONFLICT);
        } else if (!validMail(email)) {
            logger.error("Email validation failed: invalid email {}", email);
            throw new UserException(Constants.INV_EMAIL, HttpStatus.CONFLICT);
        }
    }

    public boolean validMail(String email) {
        for (String dom : Constants.URL_MAILS) {
            if (email.endsWith(dom)) {
                return true;
            }
        }
        logger.error("Invalid email format: {}", email);
        return false;
    }
}
