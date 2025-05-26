package com.user_service.user_service.services.implementations;

import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.utils.Constants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AdminServiceImplementation implements AdminService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserEntity saveUser(UserEntity user) {
        log.info(Constants.SAVING_USER, user);
        return userRepository.save(user);
    }

    @Override
    public ResponseEntity<Set<UserDTO>> getAllUsers() {
        log.info(Constants.GET_ALL_USERS);
        Set<UserDTO> users = userRepository.findAll()
                .stream()
                .map(user -> new UserDTO(user.getId(), user.getName(), user.getLastName(), user.getEmail(), user.getRole(), user.getStatus()))
                .collect(Collectors.toSet());

        log.info(Constants.GET_ALL_USERS_SUCCESSFULLY);
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @Override
    public void validateUser(Long id) {
        log.info(Constants.VALIDATE_USER, id);
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.error(Constants.USER_NOT_FOUND, id);
                    return new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
                });
        user.setStatus(UserStatus.ACTIVE);
        saveUser(user);
        log.info(Constants.VALIDATE_USER_SUCCESSFULLY);
    }

    @Override
    public ResponseEntity<UserDTO> getUserById(Long id) {
        log.info(Constants.GET_USER, id);
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> {
                    log.error(Constants.USER_NOT_FOUND, id);
                    return new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
                });

        log.info(Constants.GET_USER_SUCCESSFULLY);

        UserDTO userDTO = new UserDTO(user.getId(), user.getName(), user.getLastName(), user.getEmail(), user.getRole(), user.getStatus());
        return new ResponseEntity<>(userDTO, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<UserDTO> createAdmin(CreateUserRequest newUser) {
        log.info(Constants.CREATING_ADMIN, newUser);

        validatePassword(newUser.password());
        validateEmail(newUser.email());

        UserEntity userEntity = new UserEntity(newUser.name(), newUser.lastName(), newUser.email(), passwordEncoder.encode(newUser.password()), RoleType.ADMIN, UserStatus.ACTIVE, AuthProvider.LOCAL);
        UserEntity savedUserEntity = saveUser(userEntity);

        log.info(Constants.ADMIN_CREATED_SUCCESSFULLY);
        UserDTO userDTO = new UserDTO(savedUserEntity.getId(), savedUserEntity.getName(), savedUserEntity.getLastName(), savedUserEntity.getEmail(), savedUserEntity.getRole(), savedUserEntity.getStatus());

        return new ResponseEntity<>(userDTO, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<String> deleteUserById(Long id) {
        log.info(Constants.DELETING_USER, id);
        if (!existUserById(id)) {
            log.error(Constants.USER_NOT_FOUND, id);
            throw new UserException(Constants.USR_NOT_EXIST, HttpStatus.NOT_FOUND);
        } else {
            userRepository.deleteById(id);
            log.info(Constants.USER_DELETED_SUCCESSFULLY, id);
            return new ResponseEntity<>(Constants.SUC_DEL_USER, HttpStatus.OK);
        }
    }

    @Override
    public boolean existUserById(Long id) {
        boolean exists = userRepository.existsById(id);
        log.info("Checking existence of user with ID {}: {}", id, exists);
        return exists;
    }

    @Override
    public void validatePassword(String password) {
        if (password == null || password.isBlank()) {
            log.error(Constants.EMPTY_PASS);
            throw new UserException(Constants.EMPTY_PASS, HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public void validateEmail(String email) {
        if (existUserByEmail(email)) {
            log.error(Constants.EXIST_EMAIL + " ", email);
            throw new UserException(Constants.EXIST_EMAIL, HttpStatus.BAD_REQUEST);
        } else if (!validMail(email)) {
            log.error(Constants.INV_EMAIL + " ", email);
            throw new UserException(Constants.INV_EMAIL,  HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public boolean existUserByEmail(String email) {
        boolean exists = userRepository.existsByEmail(email);
        log.info("Checking existence of user with email {}: {}", email, exists);
        return exists;
    }

    public boolean validMail(String email) {
        for (String dom : Constants.URL_MAILS) {
            if (email.endsWith(dom)) {
                return true;
            }
        }
        log.error(Constants.INV_EMAIL + " ", email);
        return false;
    }
}
