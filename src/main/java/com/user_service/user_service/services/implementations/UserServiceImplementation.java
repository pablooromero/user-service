package com.user_service.user_service.services.implementations;

import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.exceptions.IllegalAttributeException;
import com.user_service.user_service.exceptions.UserNotFoundException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
public class UserServiceImplementation implements UserService {

    @Autowired
    private UserRepository userRepository;


    @Override
    public ResponseEntity<Long> getUserByEmail(String email) throws UserNotFoundException {
        UserEntity user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found with mail: " + email));

        return new ResponseEntity<>(user.getId(), HttpStatus.OK);
    }


    @Override
    public UserEntity saveUser(UserEntity user) {
        return userRepository.save(user);
    }


    //TODO Refactor para solo poder actualizar su perfil
    @Override
    public ResponseEntity<UserDTO> updateUser(UserDTO userDTO) throws UserNotFoundException, IllegalAttributeException {
        validateUser(userDTO);

        UserEntity existingUser = userRepository.findById(userDTO.getId())
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + userDTO.getId()));

        existingUser.setUsername(userDTO.getUsername());
        existingUser.setEmail(userDTO.getEmail());
        existingUser.setPassword(userDTO.getPassword());
        existingUser.setRole(userDTO.getRole());

        UserEntity savedUser = saveUser(existingUser);

        return new ResponseEntity<>(new UserDTO(savedUser), HttpStatus.OK);
    }

    //TODO Refactor para solo poder borrar su usuario
    @Override
    public ResponseEntity<String> deleteUser(Long id) throws UserNotFoundException {
        userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + id));

        userRepository.deleteById(id);

        return new ResponseEntity<>("User deleted!", HttpStatus.OK);
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

        if (userDTO.getUsername() == null || userDTO.getUsername().trim().isEmpty()) {
            throw new IllegalAttributeException("Username cannot be null or empty");
        }

        if (userDTO.getUsername().length() < 3) {
            throw new IllegalAttributeException("Username must be at least 3 characters long");
        }
    }

}
