package com.user_service.user_service.services.implementations;


import com.user_service.user_service.config.RabbitMQConfig;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.models.EmailEvent;
import com.user_service.user_service.exceptions.IllegalAttributeException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.AdminService;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

@Service
public class AdminServiceImplementation implements AdminService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RabbitTemplate rabbitTemplate;


    @Override
    public UserEntity saveUser(UserEntity user) {
        return userRepository.save(user);
    }


    @Override
    public ResponseEntity<List<UserEntity>> getAllUsers() {
        List<UserEntity> users = userRepository.findAll();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }


    private  UserEntity createUserBody(UserDTO userDTO) throws IllegalAttributeException {
        validateUser(userDTO);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(userDTO.getUsername());
        userEntity.setEmail(userDTO.getEmail());
        userEntity.setPassword(userDTO.getPassword());

        return userEntity;
    }

    //TODO Refactor para llamar al register
    //TODO Implementar verificación de mail
    @Override
    public ResponseEntity<UserDTO> createUser(UserDTO userDTO) throws IllegalAttributeException {

        UserEntity userEntity = createUserBody(userDTO);
        userEntity.setRole(RoleType.USER);

        UserEntity savedUser = saveUser(userEntity);

        rabbitTemplate.convertAndSend(
                RabbitMQConfig.EXCHANGE_NAME,
                "user.email",
                new EmailEvent(userDTO.getEmail(), "Bienvenido a nuestra plataforma", "Gracias por registrarte " + userDTO.getUsername())
        );

        return new ResponseEntity<>(new UserDTO(savedUser), HttpStatus.CREATED);
    }

    @Override
    public ResponseEntity<UserDTO> createAdmin(UserDTO userDTO) throws IllegalAttributeException {

        UserEntity userEntity = createUserBody(userDTO);
        userEntity.setRole(RoleType.ADMIN);

        UserEntity savedUser = saveUser(userEntity);
        return new ResponseEntity<>(new UserDTO(savedUser), HttpStatus.CREATED);
    }


    @Override
    public void validateUser(UserDTO userDTO) throws IllegalAttributeException {

        if (userDTO.getEmail() == null || userDTO.getEmail().trim().isEmpty()) {
            throw new IllegalAttributeException("Email cannot be null or empty");
        }

        String emailPattern = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        if (!Pattern.matches(emailPattern, userDTO.getEmail())) {
            throw new IllegalAttributeException("Invalid email format");
        }

        if (userRepository.existsByEmail(userDTO.getEmail())) {
            throw new IllegalAttributeException("Email is already in use");
        }

        if (userDTO.getUsername() == null || userDTO.getUsername().trim().isEmpty()) {
            throw new IllegalAttributeException("Username cannot be null or empty");
        }

        if (userDTO.getUsername().length() < 3) {
            throw new IllegalAttributeException("Username must be at least 3 characters long");
        }
    }
}
