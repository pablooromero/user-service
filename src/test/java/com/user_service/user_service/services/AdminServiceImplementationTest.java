package com.user_service.user_service.services;

import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.implementations.AdminServiceImplementation;
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
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminServiceImplementationTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AdminServiceImplementation adminService;

    private UserEntity userEntity1;
    private UserEntity adminEntity;
    private CreateUserRequest createUserRequest;

    @BeforeEach
    void setUp() {
        userEntity1 = new UserEntity(1L, "Test", "User", "test@example.com", "encodedPassword", RoleType.USER, UserStatus.PENDING, AuthProvider.LOCAL);
        adminEntity = new UserEntity(2L, "Admin", "User", "admin@example.com", "encodedAdminPassword", RoleType.ADMIN, UserStatus.ACTIVE, AuthProvider.LOCAL);
        createUserRequest = new CreateUserRequest("NewAdmin", "LastName", "newadmin@example.com", "password123");
    }

    @Test
    @DisplayName("saveUser - Debería guardar y devolver el usuario")
    void saveUser_shouldSaveAndReturnUser() {
        when(userRepository.save(any(UserEntity.class))).thenReturn(userEntity1);

        UserEntity savedUser = adminService.saveUser(userEntity1);

        assertNotNull(savedUser);
        assertEquals(userEntity1.getEmail(), savedUser.getEmail());
        verify(userRepository, times(1)).save(userEntity1);
    }

    @Test
    @DisplayName("getAllUsers - Debería devolver un Set de UserDTOs")
    void getAllUsers_shouldReturnSetOfUserDTOs() {
        List<UserEntity> userList = List.of(userEntity1, adminEntity);
        when(userRepository.findAll()).thenReturn(userList);

        ResponseEntity<Set<UserDTO>> response = adminService.getAllUsers();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(2, response.getBody().size());
        Set<String> emails = response.getBody().stream().map(UserDTO::email).collect(Collectors.toSet());
        assertTrue(emails.contains("test@example.com"));
        assertTrue(emails.contains("admin@example.com"));
    }

    @Test
    @DisplayName("validateUser - Cuando el usuario existe, debería actualizar estado a ACTIVE y guardar")
    void validateUser_whenUserExists_shouldUpdateStatusAndSave() throws UserException {
        UserEntity userToValidate = new UserEntity(1L, "Test", "User", "pending@example.com", "pass", RoleType.USER, UserStatus.PENDING, AuthProvider.LOCAL);
        when(userRepository.findById(1L)).thenReturn(Optional.of(userToValidate));
        when(userRepository.save(any(UserEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        adminService.validateUser(1L);

        verify(userRepository, times(1)).findById(1L);
        ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository, times(1)).save(userCaptor.capture());
        assertEquals(UserStatus.ACTIVE, userCaptor.getValue().getStatus());
    }

    @Test
    @DisplayName("validateUser - Cuando el usuario no existe, debería lanzar UserException")
    void validateUser_whenUserNotFound_shouldThrowUserException() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        UserException exception = assertThrows(UserException.class, () -> {
            adminService.validateUser(99L);
        });
        assertEquals(Constants.USR_NOT_EXIST, exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getHttpStatus());
        verify(userRepository, never()).save(any(UserEntity.class));
    }

    @Test
    @DisplayName("getUserById - Cuando el usuario existe, debería devolver UserDTO")
    void getUserById_whenUserExists_shouldReturnUserDTO() throws UserException {
        when(userRepository.findById(1L)).thenReturn(Optional.of(userEntity1));

        ResponseEntity<UserDTO> response = adminService.getUserById(1L);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(userEntity1.getEmail(), response.getBody().email());
    }

    @Test
    @DisplayName("getUserById - Cuando el usuario no existe, debería lanzar UserException")
    void getUserById_whenUserNotFound_shouldThrowUserException() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        UserException exception = assertThrows(UserException.class, () -> {
            adminService.getUserById(99L);
        });
        assertEquals(Constants.USR_NOT_EXIST, exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getHttpStatus());
    }

    @Test
    @DisplayName("createAdmin - Con datos válidos, debería crear admin y devolver UserDTO")
    void createAdmin_withValidData_shouldCreateAndReturnUserDTO() throws UserException {
        when(userRepository.existsByEmail(createUserRequest.email())).thenReturn(false);
        when(passwordEncoder.encode(createUserRequest.password())).thenReturn("encodedPassword123");

        UserEntity savedAdmin = new UserEntity(3L, createUserRequest.name(), createUserRequest.lastName(),
                createUserRequest.email(), "encodedPassword123", RoleType.ADMIN, UserStatus.ACTIVE, AuthProvider.LOCAL);
        when(userRepository.save(any(UserEntity.class))).thenReturn(savedAdmin);


        ResponseEntity<UserDTO> response = adminService.createAdmin(createUserRequest);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(createUserRequest.email(), response.getBody().email());
        assertEquals(RoleType.ADMIN, response.getBody().role());
        assertEquals(UserStatus.ACTIVE, response.getBody().status());
        assertNotNull(response.getBody().id());

        ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository, times(1)).save(userCaptor.capture());
        assertEquals("encodedPassword123", userCaptor.getValue().getPassword());
        assertEquals(AuthProvider.LOCAL, userCaptor.getValue().getAuthProvider());
    }

    @Test
    @DisplayName("createAdmin - Cuando el email ya existe, debería lanzar UserException")
    void createAdmin_whenEmailExists_shouldThrowUserException() {
        when(userRepository.existsByEmail(createUserRequest.email())).thenReturn(true);

        UserException exception = assertThrows(UserException.class, () -> {
            adminService.createAdmin(createUserRequest);
        });
        assertEquals(Constants.EXIST_EMAIL, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(UserEntity.class));
    }

    @Test
    @DisplayName("createAdmin - Con contraseña vacía, debería lanzar UserException")
    void createAdmin_withEmptyPassword_shouldThrowUserException() {
        CreateUserRequest requestWithEmptyPass = new CreateUserRequest("Test", "Admin", "testadmin@example.com", "");

        UserException exception = assertThrows(UserException.class, () -> {
            adminService.createAdmin(requestWithEmptyPass);
        });
        assertEquals(Constants.EMPTY_PASS, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
    }

    @Test
    @DisplayName("createAdmin - Con dominio de email inválido, debería lanzar UserException")
    void createAdmin_withInvalidEmailDomain_shouldThrowUserException() {
        CreateUserRequest requestWithInvalidEmail = new CreateUserRequest("Test", "Admin", "testadmin@invalid.domain", "password123");
        when(userRepository.existsByEmail(requestWithInvalidEmail.email())).thenReturn(false);

        UserException exception = assertThrows(UserException.class, () -> {
            adminService.createAdmin(requestWithInvalidEmail);
        });
        assertEquals(Constants.INV_EMAIL, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
    }

    @Test
    @DisplayName("deleteUserById - Cuando el usuario existe, debería eliminar y devolver mensaje de éxito")
    void deleteUserById_whenUserExists_shouldDeleteAndReturnSuccessMessage() throws UserException {
        when(userRepository.existsById(1L)).thenReturn(true);
        doNothing().when(userRepository).deleteById(1L);

        ResponseEntity<String> response = adminService.deleteUserById(1L);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(Constants.SUC_DEL_USER, response.getBody());
        verify(userRepository, times(1)).deleteById(1L);
    }

    @Test
    @DisplayName("deleteUserById - Cuando el usuario no existe, debería lanzar UserException")
    void deleteUserById_whenUserNotFound_shouldThrowUserException() {
        when(userRepository.existsById(99L)).thenReturn(false);

        UserException exception = assertThrows(UserException.class, () -> {
            adminService.deleteUserById(99L);
        });
        assertEquals(Constants.USR_NOT_EXIST, exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getHttpStatus());
        verify(userRepository, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName("existUserById - Cuando el usuario existe, debería devolver true")
    void existUserById_whenUserExists_shouldReturnTrue() throws UserException {
        when(userRepository.existsById(1L)).thenReturn(true);
        assertTrue(adminService.existUserById(1L));
    }

    @Test
    @DisplayName("existUserById - Cuando el usuario no existe, debería devolver false")
    void existUserById_whenUserDoesNotExist_shouldReturnFalse() throws UserException {
        when(userRepository.existsById(99L)).thenReturn(false);
        assertFalse(adminService.existUserById(99L));
    }

    @Test
    @DisplayName("validatePassword - Con contraseña válida, no debería lanzar excepción")
    void validatePassword_withValidPassword_shouldNotThrowException() {
        assertDoesNotThrow(() -> {
            adminService.validatePassword("validPassword123");
        });
    }

    @Test
    @DisplayName("validatePassword - Con contraseña nula, debería lanzar UserException")
    void validatePassword_withNullPassword_shouldThrowUserException() {
        UserException exception = assertThrows(UserException.class, () -> {
            adminService.validatePassword(null);
        });
        assertEquals(Constants.EMPTY_PASS, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
    }

    @Test
    @DisplayName("validatePassword - Con contraseña vacía, debería lanzar UserException")
    void validatePassword_withBlankPassword_shouldThrowUserException() {
        UserException exception = assertThrows(UserException.class, () -> {
            adminService.validatePassword("   ");
        });
        assertEquals(Constants.EMPTY_PASS, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
    }

    @Test
    @DisplayName("validateEmail - Con email nuevo y válido, no debería lanzar excepción")
    void validateEmail_withValidNewEmail_shouldNotThrowException() {
        String validNewEmail = "newuser@example.com";
        when(userRepository.existsByEmail(validNewEmail)).thenReturn(false);

        assertDoesNotThrow(() -> {
            adminService.validateEmail(validNewEmail);
        });
    }

    @Test
    @DisplayName("validateEmail - Cuando el email ya existe, debería lanzar UserException")
    void validateEmail_whenEmailExists_shouldThrowUserException() {
        String existingEmail = "existing@example.com";
        when(userRepository.existsByEmail(existingEmail)).thenReturn(true);

        UserException exception = assertThrows(UserException.class, () -> {
            adminService.validateEmail(existingEmail);
        });
        assertEquals(Constants.EXIST_EMAIL, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
    }

    @Test
    @DisplayName("validateEmail - Con dominio de email inválido, debería lanzar UserException")
    void validateEmail_withInvalidDomain_shouldThrowUserException() {
        String invalidDomainEmail = "user@invaliddomain.xyz";
        when(userRepository.existsByEmail(invalidDomainEmail)).thenReturn(false);

        UserException exception = assertThrows(UserException.class, () -> {
            adminService.validateEmail(invalidDomainEmail);
        });
        assertEquals(Constants.INV_EMAIL, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
    }

    @Test
    @DisplayName("existUserByEmail - Cuando el email existe, debería devolver true")
    void existUserByEmail_whenEmailExists_shouldReturnTrue() throws UserException {
        when(userRepository.existsByEmail("exists@example.com")).thenReturn(true);
        assertTrue(adminService.existUserByEmail("exists@example.com"));
    }

    @Test
    @DisplayName("existUserByEmail - Cuando el email no existe, debería devolver false")
    void existUserByEmail_whenEmailDoesNotExist_shouldReturnFalse() throws UserException {
        when(userRepository.existsByEmail("new@example.com")).thenReturn(false);
        assertFalse(adminService.existUserByEmail("new@example.com"));
    }

    @Test
    @DisplayName("validMail - Con dominio válido, debería devolver true")
    void validMail_withValidDomain_shouldReturnTrue() {
        assertTrue(adminService.validMail("test@example.com"));
        assertTrue(adminService.validMail("test@gmail.com"));
    }

    @Test
    @DisplayName("validMail - Con dominio inválido, debería devolver false")
    void validMail_withInvalidDomain_shouldReturnFalse() {
        assertFalse(adminService.validMail("test@unknown.xyz"));
    }

    @Test
    @DisplayName("validMail - Con email sin @, debería devolver false")
    void validMail_withNoAtSymbol_shouldReturnFalse() {
        assertFalse(adminService.validMail("testexample.com"));
    }
}
