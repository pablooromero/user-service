package com.user_service.user_service.config;

import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class SecurityUtils {

    @Autowired
    private UserRepository userRepository;

    public UserEntity getAuthenticatedUser(Authentication authentication) throws UserException {
        String username = authentication.getName();
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UserException("User not found with email: " + username));
    }
}