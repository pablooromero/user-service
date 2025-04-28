package com.user_service.user_service.config;

import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UserException {
        UserEntity userEntity = userRepository.findByEmail(username)
                .orElseThrow(() -> new UserException("User not found"));

        return new User(userEntity.getEmail(), userEntity.getPassword(), AuthorityUtils.createAuthorityList(userEntity.getRole().toString()));
    }
}
