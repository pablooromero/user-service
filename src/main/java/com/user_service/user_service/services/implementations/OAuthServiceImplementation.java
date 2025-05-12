package com.user_service.user_service.services.implementations;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.OAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OAuthServiceImplementation implements OAuthService {

    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;

    @Override
    public UserEntity findOrCreateByEmail(String email, String name, String lastName) {
        Optional<UserEntity> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isPresent()) {
            return optionalUser.get();
        }

        UserEntity newUser = new UserEntity();
        newUser.setName(name);
        newUser.setLastName(lastName);
        newUser.setPassword("");
        newUser.setEmail(email);
        newUser.setStatus(UserStatus.ACTIVE);
        newUser.setRole(RoleType.USER);
        newUser.setAuthProvider(AuthProvider.GOOGLE);
        userRepository.save(newUser);
        return newUser;
    }
}
