package com.user_service.user_service.services.implementations;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.config.RabbitMQConfig;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.Status;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.AuthService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthServiceImplementation implements AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserService userService;

    @Autowired
    private AdminService adminService;

    @Autowired
    private RabbitTemplate rabbitTemplate;

    @Override
    public ResponseEntity<String> loginUser(LoginUserRecord loginUserRecord) throws UserException {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginUserRecord.email(),
                            loginUserRecord.password()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserRegistrationRecord user = userService.getUserByEmail(loginUserRecord.email());

            if (user.userStatus() == Status.ACTIVE){
                String jwt = jwtUtils.generateToken(user.email(),user.id(),user.role().toString());

                return new ResponseEntity<>(jwt, HttpStatus.OK);
            } else {
                throw new UserException(Constants.NOT_ACTIVE, HttpStatus.UNAUTHORIZED);
            }

        } catch (BadCredentialsException e) {
            throw new UserException(Constants.INV_CRED, HttpStatus.UNAUTHORIZED);
        }
    }


    @Transactional(rollbackFor = {UserException.class})
    @Override
    public UserRecord createUser(NewUserRecord newUserRecord) throws UserException {
        adminService.validateUsername(newUserRecord.username());
        adminService.validatePassword(newUserRecord.password());
        adminService.validateEmail(newUserRecord.email());

        UserEntity userEntity = new UserEntity(newUserRecord.username(), passwordEncoder.encode(newUserRecord.password()), newUserRecord.email(), RoleType.USER);
        userEntity = userRepository.save(userEntity);
        UserRecord userRecord = new UserRecord(userEntity.getId(), userEntity.getUsername(),userEntity.getEmail(),userEntity.getRole());
        sendRegistrationEmail(userEntity);

        return userRecord;
    }

    private void sendRegistrationEmail(UserEntity userEntity){
        String jwt = jwtUtils.generateRegisterToken(userEntity.getId(),50000L);
        rabbitTemplate.convertAndSend(RabbitMQConfig.EXCHANGE_NAME, "user.email",
                new EmailEvent(userEntity.getEmail(), Constants.SUC_REG,Constants.BODY_MAIL+userEntity.getUsername()+ "\nConfirm your user here: "+"http://localhost:8080/API/auth/register/"+jwt));
    }


}
