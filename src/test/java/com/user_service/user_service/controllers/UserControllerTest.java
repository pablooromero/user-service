package com.user_service.user_service.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.config.SecurityConfig;
import com.user_service.user_service.dtos.UpdateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.ExceptionHandlers;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.OAuthService;
import com.user_service.user_service.services.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@Import({SecurityConfig.class, ExceptionHandlers.class})
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @MockBean
    private AdminService adminService;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private OAuthService oAuthService;

    @MockBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private UserDTO testUserDTO;
    private final String TEST_USER_EMAIL = "user@example.com";
    private final Long TEST_USER_ID = 1L;

    @BeforeEach
    void setUp() {
        testUserDTO = new UserDTO(TEST_USER_ID, "Test", "User", TEST_USER_EMAIL, RoleType.USER, UserStatus.ACTIVE);
    }

    @Test
    @DisplayName("GET /api/users - Debería devolver información del usuario autenticado")
    void getAuthenticatedUserInfo_whenAuthenticated_shouldReturnUserInfo() throws Exception {
        when(adminService.getUserById(eq(TEST_USER_ID))).thenReturn(ResponseEntity.ok(testUserDTO));

        // Act & Assert
        mockMvc.perform(get("/api/users")
                        .with(jwt().jwt(token -> token
                                .subject(TEST_USER_EMAIL)
                                .claim("id", TEST_USER_ID.toString())
                                .claim("role", "USER"))))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id", is(TEST_USER_ID.intValue())))
                .andExpect(jsonPath("$.email", is(TEST_USER_EMAIL)));
    }

    @Test
    @DisplayName("GET /api/users - Debería devolver 401 si no está autenticado")
    void getAuthenticatedUserInfo_notAuthenticated_shouldReturnUnauthorized() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /api/users - Debería devolver error si el token no tiene claim 'id'")
    void getAuthenticatedUserInfo_tokenMissingIdClaim_shouldReturnBadRequest() throws Exception {
        mockMvc.perform(get("/api/users")
                        .with(jwt().jwt(token -> token
                                .subject(TEST_USER_EMAIL)
                                .claim("role", "USER"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("PUT /api/users - Debería actualizar información del usuario autenticado")
    void updateUser_whenAuthenticated_shouldUpdateUser() throws Exception {
        UpdateUserRequest updateRequest = new UpdateUserRequest("UpdatedName", "UpdatedLastName", "newPassword123");
        UserDTO updatedUserDTO = new UserDTO(TEST_USER_ID, "UpdatedName", "UpdatedLastName", TEST_USER_EMAIL, RoleType.USER, UserStatus.ACTIVE);

        when(userService.updateUser(eq(TEST_USER_ID), any(UpdateUserRequest.class)))
                .thenReturn(ResponseEntity.ok(updatedUserDTO));

        mockMvc.perform(put("/api/users")
                        .with(jwt().jwt(token -> token
                                .subject(TEST_USER_EMAIL)
                                .claim("id", TEST_USER_ID.toString())
                                .claim("role", "USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name", is("UpdatedName")))
                .andExpect(jsonPath("$.lastName", is("UpdatedLastName")));
    }

    @Test
    @DisplayName("PUT /api/users - Debería devolver error si el servicio lanza UserException")
    void updateUser_whenServiceThrowsException_shouldReturnError() throws Exception {
        UpdateUserRequest updateRequest = new UpdateUserRequest("Test", "User", "password");
        when(userService.updateUser(eq(TEST_USER_ID), any(UpdateUserRequest.class)))
                .thenThrow(new UserException("Error al actualizar", HttpStatus.INTERNAL_SERVER_ERROR));

        mockMvc.perform(put("/api/users")
                        .with(jwt().jwt(token -> token
                                .subject(TEST_USER_EMAIL)
                                .claim("id", TEST_USER_ID.toString())
                                .claim("role", "USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateRequest)))
                .andExpect(status().isInternalServerError())
                .andExpect(content().string("Error al actualizar"));
    }

    @Test
    @DisplayName("DELETE /api/users - Debería eliminar la cuenta del usuario autenticado")
    void deleteUser_whenAuthenticated_shouldDeleteUser() throws Exception {
        doNothing().when(userService).deleteUserById(eq(TEST_USER_ID));

        mockMvc.perform(delete("/api/users")
                        .with(jwt().jwt(token -> token
                                .subject(TEST_USER_EMAIL)
                                .claim("id", TEST_USER_ID.toString())
                                .claim("role", "USER"))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("GET /api/users/private/email/{email} - Debería devolver ID de usuario para llamada de servicio autenticada")
    void getUserIdByEmail_whenCalledByAuthenticatedService_shouldReturnUserId() throws Exception {
        String targetEmail = "target@example.com";
        Long targetUserId = 2L;
        when(userService.getUserIdByEmail(eq(targetEmail))).thenReturn(ResponseEntity.ok(targetUserId));

        mockMvc.perform(get("/api/users/private/email/" + targetEmail)
                        .with(jwt()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", is(targetUserId.intValue())));
    }

    @Test
    @DisplayName("GET /api/users/private/email/{email} - Debería devolver 404 si el email no existe")
    void getUserIdByEmail_whenEmailNotFound_shouldReturnNotFound() throws Exception {
        String nonExistentEmail = "unknown@example.com";
        when(userService.getUserIdByEmail(eq(nonExistentEmail)))
                .thenThrow(new UserException("Usuario no encontrado por email", HttpStatus.NOT_FOUND));

        mockMvc.perform(get("/api/users/private/email/" + nonExistentEmail)
                        .with(jwt()))
                .andExpect(status().isNotFound())
                .andExpect(content().string("Usuario no encontrado por email"));
    }
}