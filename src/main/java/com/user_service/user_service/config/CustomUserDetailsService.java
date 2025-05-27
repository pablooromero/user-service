package com.user_service.user_service.config;

import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        log.info("CustomUserDetailsService: Buscando usuario con email '{}'", username); // <--- LOG INICIAL
        UserEntity userEntity = userRepository.findByEmail(username)
                .orElseThrow(() -> {
                    log.warn("CustomUserDetailsService: Usuario no encontrado con email '{}'", username); // <--- LOG NO ENCONTRADO
                    return new UsernameNotFoundException("User not found");
                });

        String role = "ROLE_NO_ROLE"; // Valor por defecto si el rol es null
        if (userEntity.getRole() != null) {
            role = "ROLE_" + userEntity.getRole().toString().toUpperCase();
            log.info("CustomUserDetailsService: Usuario '{}' encontrado con rol '{}'. Creando UserDetails.", username, role); // <--- LOG ENCONTRADO + ROL
        } else {
            log.warn("CustomUserDetailsService: ¡Usuario '{}' encontrado pero tiene ROL NULL!", username); // <--- LOG ROL NULL
        }

        return new User(userEntity.getEmail(), userEntity.getPassword(), AuthorityUtils.createAuthorityList(role));
    }
}
