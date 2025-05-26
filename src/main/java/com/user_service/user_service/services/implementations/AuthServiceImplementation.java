package com.user_service.user_service.services.implementations;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.config.RabbitMQConfig;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.AuthService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImplementation implements AuthService {

    private final AuthenticationManager authenticationManager;

    private final JwtUtils jwtUtils;

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    private final UserService userService;

    private final AdminService adminService;

    private final RabbitTemplate rabbitTemplate;

    @Override
    public ResponseEntity<String> loginUser(LoginUserDTO loginUserDTO) {
        log.info( Constants.AUTHENTICATING_USER, loginUserDTO.email());
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginUserDTO.email(),
                            loginUserDTO.password()
                    )
            );
        } catch(AuthenticationException e) {
            log.error(Constants.INV_CRED);
            throw new UserException(Constants.INV_CRED, HttpStatus.UNAUTHORIZED);
        }
            SecurityContextHolder.getContext().setAuthentication(authentication);
            RegisterUserRequest user = userService.getUserByEmail(loginUserDTO.email());

            if (user.userStatus() == UserStatus.ACTIVE) {
                String jwt = jwtUtils.generateToken(user.email(), user.id(), user.role().toString());
                log.info(Constants.USER_LOGGED_SUCCESSFULLY, loginUserDTO.email());
                return new ResponseEntity<>(jwt, HttpStatus.OK);
            } else {
                log.warn(Constants.NOT_ACTIVE + " ", loginUserDTO.email());
                throw new UserException(Constants.NOT_ACTIVE, HttpStatus.UNAUTHORIZED);
            }
    }

    @Override
    @Transactional
    public UserDTO createUser(CreateUserRequest newUser) {
        log.info(Constants.CREATING_USER, newUser.email());

        adminService.validatePassword(newUser.password());
        adminService.validateEmail(newUser.email());

        UserEntity userEntity = new UserEntity(newUser.name(), newUser.lastName(), newUser.email(), passwordEncoder.encode(newUser.password()), RoleType.USER, UserStatus.PENDING, AuthProvider.LOCAL );
        UserEntity savedUserEntity = userRepository.save(userEntity);

        UserDTO userDTO = new UserDTO(savedUserEntity.getId(), savedUserEntity.getName(), savedUserEntity.getLastName(), savedUserEntity.getEmail(), savedUserEntity.getRole(), savedUserEntity.getStatus());

        log.info(Constants.CREATED_SUCCESSFULLY, savedUserEntity.getEmail());

        sendRegistrationEmail(savedUserEntity);

        return userDTO;
    }

    private void sendRegistrationEmail(UserEntity userEntity) {
        if(userEntity.getId() == null) {
            log.error(Constants.USER_ID_NULL, userEntity.getEmail());
            return;
        }
        log.info(Constants.SENDING_REGISTRATION_MAIL, userEntity.getEmail());
        String jwt = jwtUtils.generateRegisterToken(userEntity.getId(), 50000L);

        try {
            rabbitTemplate.convertAndSend(RabbitMQConfig.EXCHANGE_NAME, "user.email",
                    new EmailEvent(userEntity.getEmail(), Constants.SUC_REG, Constants.BODY_MAIL +
                            "\nConfirm your user here: " +
                            "http://localhost:8080/api/auth/validate/" + jwt));

            log.info(Constants.SEND_EMAIL_SUCCESSFULLY, userEntity.getEmail());
        } catch (AmqpException e) {
            log.error(Constants.ERROR_SEND_REGISTRATION_EMAIL, userEntity.getId(), e.getMessage(), e);
        }
    }
}
