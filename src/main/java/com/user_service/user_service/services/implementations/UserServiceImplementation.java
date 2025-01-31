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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImplementation implements UserService {

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
        UserEntity user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found with mail: " + email));

        return new ResponseEntity<>(user.getId(), HttpStatus.OK);
    }

    @Override
    public UserRegistrationRecord getUserByEmail(String email) throws UserException {
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserException(Constants.USR_NOT_EXIST + email));

        return new UserRegistrationRecord(user.getId(), user.getUsername(),user.getEmail(),user.getRole(), user.getStatus());
    }


    @Override
    public UserEntity saveUser(UserEntity user) {
        return userRepository.save(user);
    }


    @Override
    public ResponseEntity<UserRecord> updateUser(Long id, UpdateUserRecord updateUserRecord) throws UserException {
        adminService.validateUsername(updateUserRecord.username());
        adminService.validatePassword(updateUserRecord.password());

        UserEntity user = userRepository.findById(id)
                .orElseThrow(()->new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND));

        user.setUsername(updateUserRecord.username());
        user.setPassword(updateUserRecord.password());

        user = saveUser(user);

        return new ResponseEntity<>(new UserRecord(user.getId(), user.getUsername(),user.getEmail(),user.getRole()), HttpStatus.OK);

    }


    @Override
    public void deleteUserById(Long id) throws UserException {
        if (!adminService.existUserById(id)){
            throw new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
        }else {
            userRepository.deleteById(id);
        }

    }

    @Override
    public AuthResponseDTO changePassword(ChangePasswordDTO changePasswordDTO, Authentication authentication) throws UserNotFoundException {
        UserEntity user = securityUtils.getAuthenticatedUser(authentication);

        if (!passwordEncoder.matches(changePasswordDTO.getCurrentPassword(), user.getPassword())) {
            return new AuthResponseDTO("-", "Current password is incorrect");
        }

        if (changePasswordDTO.getNewPassword().length() < 8) {
            return new AuthResponseDTO("-", "New password must be at least 8 characters long");
        }

        if (passwordEncoder.matches(changePasswordDTO.getNewPassword(), user.getPassword())) {
            return new AuthResponseDTO("-", "New password cannot be the same as the current password");
        }

        user.setPassword(passwordEncoder.encode(changePasswordDTO.getNewPassword()));
        saveUser(user);

        return new AuthResponseDTO("-", "Password updated successfully");
    }


}
