package com.user_service.user_service.services.implementations;

import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.utils.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AdminServiceImplementation implements AdminService {

    private static final Logger logger = LoggerFactory.getLogger(AdminServiceImplementation.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserEntity saveUser(UserEntity user) {
        logger.info(Constants.SAVING_USER, user);
        return userRepository.save(user);
    }

    @Override
    public ResponseEntity<Set<UserDTO>> getAllUsers() {
        logger.info(Constants.GET_ALL_USERS);
        Set<UserDTO> users = userRepository.findAll()
                .stream()
                .map(user -> new UserDTO(user.getId(), user.getName(), user.getLastName(), user.getEmail(), user.getRole(), user.getStatus()))
                .collect(Collectors.toSet());

        logger.info(Constants.GET_ALL_USERS_SUCCESSFULLY);
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @Override
    public void validateUser(Long id) throws UserException {
        logger.info(Constants.VALIDATE_USER, id);
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.error(Constants.USER_NOT_FOUND, id);
                    return new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
                });
        user.setStatus(UserStatus.ACTIVE);
        saveUser(user);
        logger.info(Constants.VALIDATE_USER_SUCCESSFULLY);
    }

    @Override
    public ResponseEntity<UserDTO> getUserById(Long id) throws UserException {
        logger.info(Constants.GET_USER, id);
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.error(Constants.USER_NOT_FOUND, id);
                    return new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
                });

        logger.info(Constants.GET_USER_SUCCESSFULLY);

        UserDTO userDTO = new UserDTO(user.getId(), user.getName(), user.getLastName(), user.getEmail(), user.getRole(), user.getStatus());
        return new ResponseEntity<>(userDTO, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<UserDTO> createAdmin(CreateUserRequest newUser) throws UserException {
        logger.info(Constants.CREATING_ADMIN, newUser);

        validatePassword(newUser.password());
        validateEmail(newUser.email());

        UserEntity userEntity = new UserEntity(newUser.name(), newUser.lastName(), newUser.email(), passwordEncoder.encode(newUser.password()), RoleType.ADMIN, UserStatus.ACTIVE);
        saveUser(userEntity);

        logger.info(Constants.ADMIN_CREATED_SUCCESSFULLY);
        UserDTO userDTO = new UserDTO(userEntity.getId(), userEntity.getName(), userEntity.getLastName(), userEntity.getEmail(), userEntity.getRole(), userEntity.getStatus());

        return new ResponseEntity<>(userDTO, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<String> deleteUserById(Long id) throws UserException {
        logger.info(Constants.DELETING_USER, id);
        if (!existUserById(id)) {
            logger.error(Constants.USER_NOT_FOUND, id);
            throw new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
        } else {
            userRepository.deleteById(id);
            logger.info(Constants.USER_DELETED_SUCCESSFULLY, id);
            return new ResponseEntity<>(Constants.SUC_DEL_USER, HttpStatus.OK);
        }
    }

    @Override
    public boolean existUserById(Long id) throws UserException {
        boolean exists = userRepository.existsById(id);
        logger.info("Checking existence of user with ID {}: {}", id, exists);
        return exists;
    }

    @Override
    public void validatePassword(String password) throws UserException {
        if (password == null || password.isBlank()) {
            logger.error(Constants.EMPTY_PASS);
            throw new UserException(Constants.EMPTY_PASS, HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public void validateEmail(String email) throws UserException {
        if (existUserByEmail(email)) {
            logger.error(Constants.EXIST_EMAIL + " ", email);
            throw new UserException(Constants.EXIST_EMAIL, HttpStatus.BAD_REQUEST);
        } else if (!validMail(email)) {
            logger.error(Constants.INV_EMAIL + " ", email);
            throw new UserException(Constants.INV_EMAIL,  HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public boolean existUserByEmail(String email) throws UserException {
        boolean exists = userRepository.existsByEmail(email);
        logger.info("Checking existence of user with email {}: {}", email, exists);
        return exists;
    }

    public boolean validMail(String email) {
        for (String dom : Constants.URL_MAILS) {
            if (email.endsWith(dom)) {
                return true;
            }
        }
        logger.error(Constants.INV_EMAIL + " ", email);
        return false;
    }
}
