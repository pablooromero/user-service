package com.user_service.user_service.services;

import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.implementations.OAuthServiceImplementation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuthServiceImplementationTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private OAuthServiceImplementation oAuthService;

    private UserEntity existingUser;
    private String testEmail;
    private String testName;
    private String testLastName;

    @BeforeEach
    void setUp() {
        testEmail = "test@example.com";
        testName = "Test";
        testLastName = "User";

        existingUser = new UserEntity();
        existingUser.setId(1L);
        existingUser.setEmail(testEmail);
        existingUser.setName(testName);
        existingUser.setLastName(testLastName);
        existingUser.setRole(RoleType.USER);
        existingUser.setStatus(UserStatus.ACTIVE);
        existingUser.setAuthProvider(AuthProvider.LOCAL);
        existingUser.setPassword("someExistingPassword");
    }

    @Test
    @DisplayName("findOrCreateByEmail - Debería devolver usuario existente si se encuentra por email")
    void findOrCreateByEmail_whenUserExists_shouldReturnExistingUser() {
        when(userRepository.findByEmail(testEmail)).thenReturn(Optional.of(existingUser));

        UserEntity result = oAuthService.findOrCreateByEmail(testEmail, testName, testLastName);

        assertNotNull(result);
        assertEquals(existingUser.getId(), result.getId());
        assertEquals(existingUser.getEmail(), result.getEmail());
        assertEquals(existingUser.getName(), result.getName());
        assertEquals(existingUser.getLastName(), result.getLastName());
        assertEquals(existingUser.getRole(), result.getRole());
        assertEquals(existingUser.getStatus(), result.getStatus());
        assertEquals(existingUser.getAuthProvider(), result.getAuthProvider());
        verify(userRepository, times(1)).findByEmail(testEmail);
        verify(userRepository, never()).save(any(UserEntity.class));
    }

    @Test
    @DisplayName("findOrCreateByEmail - Debería crear y devolver nuevo usuario si no se encuentra por email")
    void findOrCreateByEmail_whenUserDoesNotExist_shouldCreateAndReturnNewUser() {
        String newEmail = "newuser@example.com";
        String newName = "New";
        String newLastName = "UserGoogle";

        UserEntity newlySavedUser = new UserEntity();
        newlySavedUser.setId(2L);
        newlySavedUser.setEmail(newEmail);
        newlySavedUser.setName(newName);
        newlySavedUser.setLastName(newLastName);
        newlySavedUser.setPassword("");
        newlySavedUser.setRole(RoleType.USER);
        newlySavedUser.setStatus(UserStatus.ACTIVE);
        newlySavedUser.setAuthProvider(AuthProvider.GOOGLE);

        when(userRepository.findByEmail(newEmail)).thenReturn(Optional.empty());
        when(userRepository.save(any(UserEntity.class))).thenReturn(newlySavedUser);

        UserEntity result = oAuthService.findOrCreateByEmail(newEmail, newName, newLastName);

        assertNotNull(result);
        assertEquals(newlySavedUser.getId(), result.getId());
        assertEquals(newEmail, result.getEmail());
        assertEquals(newName, result.getName());
        assertEquals(newLastName, result.getLastName());
        assertEquals("", result.getPassword(), "La contraseña para un nuevo usuario OAuth2 debería estar vacía");
        assertEquals(RoleType.USER, result.getRole());
        assertEquals(UserStatus.ACTIVE, result.getStatus());
        assertEquals(AuthProvider.GOOGLE, result.getAuthProvider());

        verify(userRepository, times(1)).findByEmail(newEmail);

        ArgumentCaptor<UserEntity> userEntityCaptor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository, times(1)).save(userEntityCaptor.capture());

        UserEntity capturedUser = userEntityCaptor.getValue();
        assertNull(capturedUser.getId(), "El ID debería ser null ANTES de llamar a save");
        assertEquals(newEmail, capturedUser.getEmail());
        assertEquals(newName, capturedUser.getName());
        assertEquals(newLastName, capturedUser.getLastName());
        assertEquals("", capturedUser.getPassword());
        assertEquals(RoleType.USER, capturedUser.getRole());
        assertEquals(UserStatus.ACTIVE, capturedUser.getStatus());
        assertEquals(AuthProvider.GOOGLE, capturedUser.getAuthProvider());
    }
}