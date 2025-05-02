package com.user_service.user_service.services.implementations;

import com.user_service.user_service.config.SecurityUtils;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImplementation implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImplementation.class);

    private final UserRepository userRepository;

    private final AdminService adminService;

    private final SecurityUtils securityUtils;

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserEntity saveUser(UserEntity user) {
        logger.info(Constants.SAVING_USER, user.getEmail());
        UserEntity savedUser = userRepository.save(user);
        logger.info(Constants.USER_SAVED_SUCCESSFULLY, user.getEmail());
        return savedUser;
    }

    @Override
    public ResponseEntity<Long> getUserIdByEmail(String email) throws UserException {
        logger.info(Constants.GET_USER_BY_EMAIL, email);

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn(Constants.GET_USER_BY_EMAIL, email);
                    return new UserException(Constants.USER_NOT_FOUND_WITH_EMAIL + email, HttpStatus.NOT_FOUND);
                });

        logger.info(Constants.GET_USER_BY_EMAIL_SUCCESSFULLY, user.getEmail());

        return new ResponseEntity<>(user.getId(), HttpStatus.OK);
    }

    @Override
    public RegisterUserRequest getUserByEmail(String email) throws UserException {
        logger.info(Constants.GET_USER_BY_EMAIL, email);
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn(Constants.USER_NOT_FOUND_WITH_EMAIL, email);
                    return new UserException(Constants.USR_NOT_EXIST + email, HttpStatus.NOT_FOUND);
                });

        logger.info(Constants.USER_NOT_FOUND_WITH_EMAIL, email);
        return new RegisterUserRequest(user.getId(), user.getName(), user.getLastName(), user.getEmail(), user.getStatus(), user.getRole());
    }

    @Override
    public ResponseEntity<UserDTO> updateUser(Long id, UpdateUserRequest updateUser) throws UserException {
        logger.info(Constants.UPDATING_USER, id);

        adminService.validatePassword(updateUser.password());

        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.warn(Constants.USER_NOT_FOUND, id);
                    return new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
                });

        user.setName(updateUser.name());
        user.setLastName(updateUser.lastName());

        saveUser(user);

        logger.info(Constants.UPDATE_USER_SUCCESSFULLY, user.getEmail());

        UserDTO userDTO = new UserDTO(user.getId(), user.getName(), user.getLastName(), user.getEmail(), user.getRole(), user.getStatus());

        return new ResponseEntity<>(userDTO, HttpStatus.OK);
    }

    @Override
    public void deleteUserById(Long id) throws UserException {
        logger.info(Constants.DELETING_USER, id);
        if (!adminService.existUserById(id)) {
            logger.warn(Constants.USER_NOT_FOUND, id);
            throw new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
        } else {
            userRepository.deleteById(id);
            logger.info(Constants.USER_DELETED_SUCCESSFULLY, id);
        }
    }

    @Override
    public AuthDTO changePassword(ChangePasswordRequest changePasswordRequest, Authentication authentication) throws UserException {
        logger.info(Constants.CHANGING_PASSWORD);
        UserEntity user = securityUtils.getAuthenticatedUser(authentication);

        if (!passwordEncoder.matches(changePasswordRequest.currentPassword(), user.getPassword())) {
            logger.warn(Constants.CURRENT_PASSWORD_INCORRECT, user.getEmail());
            return new AuthDTO("-", "Current password is incorrect");
        }

        if (changePasswordRequest.newPassword().length() < 8) {
            logger.warn(Constants.NEW_PASSWORD_TOO_SHORT, user.getEmail());
            return new AuthDTO("-", "New password must be at least 8 characters long");
        }

        if (passwordEncoder.matches(changePasswordRequest.newPassword(), user.getPassword())) {
            logger.warn(Constants.NEW_PASSWORD_SAME, user.getEmail());
            return new AuthDTO("-", "New password cannot be the same as the current password");
        }

        user.setPassword(passwordEncoder.encode(changePasswordRequest.newPassword()));
        saveUser(user);

        logger.info(Constants.PASSWORD_UPDATED_SUCCESSFULLY, user.getEmail());
        return new AuthDTO("-", "Password updated successfully");
    }
}
