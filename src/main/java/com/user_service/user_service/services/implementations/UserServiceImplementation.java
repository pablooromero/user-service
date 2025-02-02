package com.user_service.user_service.services.implementations;

import com.user_service.user_service.config.SecurityUtils;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.exceptions.UserNotFoundException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImplementation implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImplementation.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityUtils securityUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AdminService adminService;

    @Override
    public ResponseEntity<Long> getUserIdByEmail(String email) throws UserNotFoundException {
        logger.info("Fetching user ID by email: {}", email);
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("User not found with email: {}", email);
                    return new UserNotFoundException("User not found with email: " + email);
                });

        logger.info("User ID {} found for email: {}", user.getId(), email);
        return new ResponseEntity<>(user.getId(), HttpStatus.OK);
    }

    @Override
    public UserRegistrationRecord getUserByEmail(String email) throws UserException {
        logger.info("Fetching user by email: {}", email);
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("User not found with email: {}", email);
                    return new UserException(Constants.USR_NOT_EXIST + email);
                });

        logger.info("User found: {} with email: {}", user.getUsername(), email);
        return new UserRegistrationRecord(user.getId(), user.getUsername(), user.getEmail(), user.getRole(), user.getStatus());
    }

    @Override
    public UserEntity saveUser(UserEntity user) {
        logger.info("Saving user: {}", user.getUsername());
        UserEntity savedUser = userRepository.save(user);
        logger.info("User {} saved successfully with ID: {}", user.getUsername(), savedUser.getId());
        return savedUser;
    }

    @Override
    public ResponseEntity<UserRecord> updateUser(Long id, UpdateUserRecord updateUserRecord) throws UserException {
        logger.info("Updating user with ID: {}", id);
        adminService.validateUsername(updateUserRecord.username());
        adminService.validatePassword(updateUserRecord.password());

        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.warn("User not found with ID: {}", id);
                    return new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
                });

        user.setUsername(updateUserRecord.username());
        user.setPassword(updateUserRecord.password());

        user = saveUser(user);

        logger.info("User with ID {} updated successfully", id);
        return new ResponseEntity<>(new UserRecord(user.getId(), user.getUsername(), user.getEmail(), user.getRole()), HttpStatus.OK);
    }

    @Override
    public void deleteUserById(Long id) throws UserException {
        logger.info("Attempting to delete user with ID: {}", id);
        if (!adminService.existUserById(id)) {
            logger.warn("User with ID {} does not exist", id);
            throw new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
        } else {
            userRepository.deleteById(id);
            logger.info("User with ID {} deleted successfully", id);
        }
    }

    @Override
    public AuthResponseDTO changePassword(ChangePasswordDTO changePasswordDTO, Authentication authentication) throws UserNotFoundException {
        logger.info("Changing password for authenticated user");
        UserEntity user = securityUtils.getAuthenticatedUser(authentication);

        if (!passwordEncoder.matches(changePasswordDTO.getCurrentPassword(), user.getPassword())) {
            logger.warn("Current password is incorrect for user: {}", user.getUsername());
            return new AuthResponseDTO("-", "Current password is incorrect");
        }

        if (changePasswordDTO.getNewPassword().length() < 8) {
            logger.warn("New password is too short for user: {}", user.getUsername());
            return new AuthResponseDTO("-", "New password must be at least 8 characters long");
        }

        if (passwordEncoder.matches(changePasswordDTO.getNewPassword(), user.getPassword())) {
            logger.warn("New password is the same as the current password for user: {}", user.getUsername());
            return new AuthResponseDTO("-", "New password cannot be the same as the current password");
        }

        user.setPassword(passwordEncoder.encode(changePasswordDTO.getNewPassword()));
        saveUser(user);

        logger.info("Password updated successfully for user: {}", user.getUsername());
        return new AuthResponseDTO("-", "Password updated successfully");
    }
}
