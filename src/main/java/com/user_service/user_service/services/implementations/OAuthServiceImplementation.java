package com.user_service.user_service.services.implementations;

import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.OAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OAuthServiceImplementation implements OAuthService {

    private final UserRepository userRepository;

    @Override
    @Transactional
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

        UserEntity savedUser = userRepository.save(newUser);
        return savedUser;
    }
}
