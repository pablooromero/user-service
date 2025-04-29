package com.user_service.user_service.services.implementations;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.config.RabbitMQConfig;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.AuthService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImplementation implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImplementation.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private AdminService adminService;

    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Override
    public ResponseEntity<String> loginUser(LoginUserDTO loginUserDTO) throws UserException {
        logger.info( Constants.AUTHENTICATING_USER, loginUserDTO.email());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginUserDTO.email(),
                            loginUserDTO.password()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            RegisterUserRequest user = userService.getUserByEmail(loginUserDTO.email());

            if (user.userStatus() == UserStatus.ACTIVE) {
                String jwt = jwtUtils.generateToken(user.email(), user.id(), user.role().toString());
                logger.info(Constants.USER_LOGGED_SUCCESSFULLY, loginUserDTO.email());
                return new ResponseEntity<>(jwt, HttpStatus.OK);
            } else {
                logger.warn(Constants.NOT_ACTIVE + " ", loginUserDTO.email());
                throw new UserException(Constants.NOT_ACTIVE, HttpStatus.UNAUTHORIZED);
            }

        } catch (UserException e) {
            logger.error(Constants.INV_CRED);
            throw new UserException(Constants.INV_CRED, HttpStatus.UNAUTHORIZED);
        }
    }

    @Override
    public UserDTO createUser(CreateUserRequest newUser) throws UserException {
        logger.info(Constants.CREATING_USER, newUser.email());

        adminService.validatePassword(newUser.password());
        adminService.validateEmail(newUser.email());

        UserEntity userEntity = new UserEntity(newUser.name(), newUser.lastName(), newUser.email(), passwordEncoder.encode(newUser.password()), RoleType.USER, UserStatus.PENDING );
        userRepository.save(userEntity);

        UserDTO userDTO = new UserDTO(userEntity.getId(), userEntity.getName(), userEntity.getLastName(), userEntity.getEmail(), userEntity.getRole(), userEntity.getStatus());

        logger.info(Constants.CREATED_SUCCESSFULLY, userEntity.getEmail());

        sendRegistrationEmail(userEntity);

        return userDTO;
    }

    private void sendRegistrationEmail(UserEntity userEntity) {
        logger.info(Constants.SENDING_REGISTRATION_MAIL, userEntity.getEmail());
        String jwt = jwtUtils.generateRegisterToken(userEntity.getId(), 50000L);

        rabbitTemplate.convertAndSend(RabbitMQConfig.EXCHANGE_NAME, "user.email",
                new EmailEvent(userEntity.getEmail(), Constants.SUC_REG, Constants.BODY_MAIL +
                        "\nConfirm your user here: " +
                        "http://localhost:8080/api/auth/validate/" + jwt));

        logger.info(Constants.SEND_EMAIL_SUCCESSFULLY, userEntity.getEmail());
    }

}
