package com.user_service.user_service.services;

import com.user_service.user_service.config.SecurityUtils;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.implementations.UserServiceImplementation;
import com.user_service.user_service.utils.Constants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;


import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplementationTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AdminService adminService;

    @Mock
    private SecurityUtils securityUtils;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImplementation userService;

    private UserEntity testUser;
    private UserDTO testUserDTO;
    private UpdateUserRequest updateUserRequest;
    private ChangePasswordRequest changePasswordRequest;
    private Authentication mockAuthentication;

    @BeforeEach
    void setUp() {
        testUser = new UserEntity(1L, "Test", "User", "test@example.com", "encodedPassword", RoleType.USER, UserStatus.ACTIVE, AuthProvider.LOCAL);
        testUserDTO = new UserDTO(1L, "Test", "User", "test@example.com", RoleType.USER, UserStatus.ACTIVE);
        updateUserRequest = new UpdateUserRequest("UpdatedName", "UpdatedLastName", "newPassword123");
        changePasswordRequest = new ChangePasswordRequest("oldPassword", "newValidPassword123");
        mockAuthentication = mock(Authentication.class);
    }

    @Test
    @DisplayName("saveUser - Debería guardar y devolver el usuario")
    void saveUser_shouldSaveAndReturnUser() {
        when(userRepository.save(any(UserEntity.class))).thenReturn(testUser);

        UserEntity savedUser = userService.saveUser(testUser);

        assertNotNull(savedUser);
        assertEquals(testUser.getEmail(), savedUser.getEmail());
        verify(userRepository, times(1)).save(testUser);
    }

    @Test
    @DisplayName("getUserIdByEmail - Cuando el usuario existe, debería devolver el ID del usuario")
    void getUserIdByEmail_whenUserExists_shouldReturnUserId() throws UserException {
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));

        ResponseEntity<Long> response = userService.getUserIdByEmail(testUser.getEmail());

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(testUser.getId(), response.getBody());
    }

    @Test
    @DisplayName("getUserIdByEmail - Cuando el usuario no existe, debería lanzar UserException")
    void getUserIdByEmail_whenUserNotFound_shouldThrowUserException() {
        String nonExistentEmail = "notfound@example.com";
        when(userRepository.findByEmail(nonExistentEmail)).thenReturn(Optional.empty());

        UserException exception = assertThrows(UserException.class, () -> {
            userService.getUserIdByEmail(nonExistentEmail);
        });
        assertEquals(Constants.USER_NOT_FOUND_WITH_EMAIL + nonExistentEmail, exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getHttpStatus());
    }

    @Test
    @DisplayName("getUserByEmail (Devuelve RegisterUserRequest) - Cuando el usuario existe, debería devolver DTO")
    void getUserByEmail_dto_whenUserExists_shouldReturnRegisterUserRequest() throws UserException {
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));

        RegisterUserRequest result = userService.getUserByEmail(testUser.getEmail());

        assertNotNull(result);
        assertEquals(testUser.getId(), result.id());
        assertEquals(testUser.getName(), result.name());
        assertEquals(testUser.getEmail(), result.email());
        assertEquals(testUser.getRole(), result.role());
        assertEquals(testUser.getStatus(), result.userStatus());
    }

    @Test
    @DisplayName("getUserByEmail (Devuelve RegisterUserRequest) - Cuando el usuario no existe, debería lanzar UserException")
    void getUserByEmail_dto_whenUserNotFound_shouldThrowUserException() {
        String nonExistentEmail = "notfound@example.com";
        when(userRepository.findByEmail(nonExistentEmail)).thenReturn(Optional.empty());

        UserException exception = assertThrows(UserException.class, () -> {
            userService.getUserByEmail(nonExistentEmail);
        });
        assertEquals(Constants.USR_NOT_EXIST + nonExistentEmail, exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getHttpStatus());
    }


    @Test
    @DisplayName("updateUser - Cuando el usuario existe y la validación de contraseña pasa, debería actualizar y devolver UserDTO")
    void updateUser_whenUserExistsAndValidationPasses_shouldUpdateAndReturnUserDTO() throws UserException {
        doNothing().when(adminService).validatePassword(updateUserRequest.password());
        when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(UserEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        ResponseEntity<UserDTO> response = userService.updateUser(testUser.getId(), updateUserRequest);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(updateUserRequest.name(), response.getBody().name());
        assertEquals(updateUserRequest.lastName(), response.getBody().lastName());
        verify(adminService, times(1)).validatePassword(updateUserRequest.password());
        verify(userRepository, times(1)).save(any(UserEntity.class));
    }

    @Test
    @DisplayName("updateUser - Cuando el usuario no existe, debería lanzar UserException")
    void updateUser_whenUserNotFound_shouldThrowUserException() throws UserException {
        doNothing().when(adminService).validatePassword(updateUserRequest.password());
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        UserException exception = assertThrows(UserException.class, () -> {
            userService.updateUser(99L, updateUserRequest);
        });
        assertEquals(Constants.USR_NOT_EXIST, exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getHttpStatus());
    }

    @Test
    @DisplayName("updateUser - Cuando la validación de contraseña falla, debería lanzar UserException")
    void updateUser_whenPasswordValidationFails_shouldThrowUserException() throws UserException {
        doThrow(new UserException(Constants.EMPTY_PASS, HttpStatus.BAD_REQUEST))
                .when(adminService).validatePassword(updateUserRequest.password());

        UserException exception = assertThrows(UserException.class, () -> {
            userService.updateUser(testUser.getId(), updateUserRequest);
        });
        assertEquals(Constants.EMPTY_PASS, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
        verify(userRepository, never()).findById(anyLong());
        verify(userRepository, never()).save(any(UserEntity.class));
    }

    @Test
    @DisplayName("deleteUserById - Cuando el usuario existe, debería eliminarlo")
    void deleteUserById_whenUserExists_shouldDeleteUser() throws UserException {
        when(adminService.existUserById(testUser.getId())).thenReturn(true);
        doNothing().when(userRepository).deleteById(testUser.getId());

        assertDoesNotThrow(() -> userService.deleteUserById(testUser.getId()));

        verify(adminService, times(1)).existUserById(testUser.getId());
        verify(userRepository, times(1)).deleteById(testUser.getId());
    }

    @Test
    @DisplayName("deleteUserById - Cuando el usuario no existe, debería lanzar UserException")
    void deleteUserById_whenUserNotFound_shouldThrowUserException() throws UserException {
        when(adminService.existUserById(99L)).thenReturn(false);

        UserException exception = assertThrows(UserException.class, () -> {
            userService.deleteUserById(99L);
        });
        assertEquals(Constants.USR_NOT_EXIST, exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getHttpStatus());
        verify(userRepository, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName("findByEmail - Cuando el usuario existe, debería devolver UserEntity")
    void findByEmail_whenUserExists_shouldReturnUserEntity() throws UserException {
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));

        UserEntity foundUser = userService.findByEmail(testUser.getEmail());

        assertNotNull(foundUser);
        assertEquals(testUser.getEmail(), foundUser.getEmail());
    }

    @Test
    @DisplayName("findByEmail - Cuando el usuario no existe, debería lanzar UserException")
    void findByEmail_whenUserNotFound_shouldThrowUserException() {
        String nonExistentEmail = "notfound@example.com";
        when(userRepository.findByEmail(nonExistentEmail)).thenReturn(Optional.empty());

        UserException exception = assertThrows(UserException.class, () -> {
            userService.findByEmail(nonExistentEmail);
        });
        assertEquals(Constants.USER_NOT_FOUND_WITH_EMAIL + nonExistentEmail, exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getHttpStatus());
    }

    @Test
    @DisplayName("changePassword - Con datos válidos, debería actualizar contraseña y devolver mensaje de éxito")
    void changePassword_withValidData_shouldUpdatePasswordAndSucceed() throws UserException {
        when(securityUtils.getAuthenticatedUser(mockAuthentication)).thenReturn(testUser);
        when(passwordEncoder.matches(changePasswordRequest.currentPassword(), testUser.getPassword())).thenReturn(true);
        when(passwordEncoder.matches(changePasswordRequest.newPassword(), testUser.getPassword())).thenReturn(false);
        when(passwordEncoder.encode(changePasswordRequest.newPassword())).thenReturn("encodedNewPassword");
        when(userRepository.save(any(UserEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));


        AuthDTO response = userService.changePassword(changePasswordRequest, mockAuthentication);

        assertEquals("Password updated successfully", response.message());
        verify(passwordEncoder, times(1)).encode(changePasswordRequest.newPassword());
        ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository, times(1)).save(userCaptor.capture());
        assertEquals("encodedNewPassword", userCaptor.getValue().getPassword());
    }

    @Test
    @DisplayName("changePassword - Con contraseña actual incorrecta, debería devolver mensaje de error")
    void changePassword_withInvalidCurrentPassword_shouldReturnError() throws UserException {
        when(securityUtils.getAuthenticatedUser(mockAuthentication)).thenReturn(testUser);
        when(passwordEncoder.matches(changePasswordRequest.currentPassword(), testUser.getPassword())).thenReturn(false);

        AuthDTO response = userService.changePassword(changePasswordRequest, mockAuthentication);

        assertEquals("Current password is incorrect", response.message());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(UserEntity.class));
    }

    @Test
    @DisplayName("changePassword - Con nueva contraseña demasiado corta, debería devolver mensaje de error")
    void changePassword_withNewPasswordTooShort_shouldReturnError() throws UserException {
        ChangePasswordRequest shortPasswordRequest = new ChangePasswordRequest("oldPassword", "short");
        when(securityUtils.getAuthenticatedUser(mockAuthentication)).thenReturn(testUser);
        when(passwordEncoder.matches(shortPasswordRequest.currentPassword(), testUser.getPassword())).thenReturn(true);

        AuthDTO response = userService.changePassword(shortPasswordRequest, mockAuthentication);

        assertEquals("New password must be at least 8 characters long", response.message());
    }

    @Test
    @DisplayName("changePassword - Con nueva contraseña igual a la actual, debería devolver mensaje de error")
    void changePassword_withNewPasswordSameAsCurrent_shouldReturnError() throws UserException {
        when(securityUtils.getAuthenticatedUser(mockAuthentication)).thenReturn(testUser);
        when(passwordEncoder.matches(changePasswordRequest.currentPassword(), testUser.getPassword())).thenReturn(true);
        when(passwordEncoder.matches(changePasswordRequest.newPassword(), testUser.getPassword())).thenReturn(true);

        AuthDTO response = userService.changePassword(changePasswordRequest, mockAuthentication);

        assertEquals("New password cannot be the same as the current password", response.message());
    }

    @Test
    @DisplayName("changePassword - Cuando SecurityUtils lanza UserException, debería propagarla")
    void changePassword_whenUserNotFoundBySecurityUtils_shouldThrowUserException() throws UserException {
        UserException expectedException = new UserException("User not found from auth", HttpStatus.UNAUTHORIZED);
        when(securityUtils.getAuthenticatedUser(mockAuthentication)).thenThrow(expectedException);

        UserException actualException = assertThrows(UserException.class, () -> {
            userService.changePassword(changePasswordRequest, mockAuthentication);
        });
        assertEquals(expectedException.getMessage(), actualException.getMessage());
        assertEquals(expectedException.getHttpStatus(), actualException.getHttpStatus());
    }
}

