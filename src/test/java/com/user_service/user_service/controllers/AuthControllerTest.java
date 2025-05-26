package com.user_service.user_service.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.config.SecurityConfig;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.ExceptionHandlers;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.AuthService;
import com.user_service.user_service.services.OAuthService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
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
import org.springframework.security.core.Authentication;
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


@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, ExceptionHandlers.class})
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

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
    private LoginUserDTO loginUserDTO;
    private CreateUserRequest createUserRequest;

    @BeforeEach
    void setUp() {
        testUserDTO = new UserDTO(1L, "Test", "User", "test@example.com", RoleType.USER, UserStatus.ACTIVE);
        loginUserDTO = new LoginUserDTO("test@example.com", "password");
        createUserRequest = new CreateUserRequest("Test", "User", "test@example.com", "password");
    }

    @Test
    @DisplayName("POST /api/auth/login - Debería devolver JWT con credenciales válidas")
    void login_withValidCredentials_shouldReturnJwt() throws Exception {
        String jwtToken = "mocked.jwt.token";
        when(authService.loginUser(any(LoginUserDTO.class)))
                .thenReturn(ResponseEntity.ok("{\"token\": \"" + jwtToken + "\"}"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUserDTO)))
                .andExpect(status().isOk())
                .andExpect(content().contentType("text/plain;charset=UTF-8"))
                .andExpect(jsonPath("$.token", is(jwtToken)));
    }

    @Test
    @DisplayName("POST /api/auth/login - Debería devolver 401 con credenciales inválidas")
    void login_withInvalidCredentials_shouldReturnUnauthorized() throws Exception {
        String errorMessage = Constants.INV_CRED;

        when(authService.loginUser(any(LoginUserDTO.class)))
                .thenThrow(new UserException(Constants.INV_CRED, HttpStatus.UNAUTHORIZED));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUserDTO)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", is(errorMessage)));
    }

    @Test
    @DisplayName("POST /api/auth/register - Debería registrar usuario y devolver UserDTO")
    void registerUser_withValidData_shouldRegisterAndReturnUserDTO() throws Exception {
        when(authService.createUser(any(CreateUserRequest.class)))
                .thenReturn(testUserDTO);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createUserRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.email", is(testUserDTO.email())))
                .andExpect(jsonPath("$.name", is(testUserDTO.name())));
    }

    @Test
    @DisplayName("POST /api/auth/register - Debería devolver 409 si usuario ya existe")
    void registerUser_whenUserExists_shouldReturnConflict() throws Exception {
        String errorMessage = Constants.EXIST_EMAIL;

        when(authService.createUser(any(CreateUserRequest.class)))
                .thenThrow(new UserException(errorMessage, HttpStatus.CONFLICT));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createUserRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message", is(errorMessage)));
    }

    @Test
    @DisplayName("GET /api/auth/google-login - Debería redirigir a /oauth2/authorization/google")
    void googleLogin_shouldRedirectToGoogleOAuth() throws Exception {
        mockMvc.perform(get("/api/auth/google-login"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/oauth2/authorization/google"));
    }

    @Test
    @DisplayName("PUT /api/auth/change-password - Debería cambiar contraseña para usuario autenticado")
    void changePassword_whenAuthenticated_shouldChangePassword() throws Exception {
        ChangePasswordRequest changeRequest = new ChangePasswordRequest("oldPassword", "newPassword");
        AuthDTO authResponse = new AuthDTO(null, "Password updated successfully");
        when(userService.changePassword(eq(changeRequest), any(Authentication.class)))
                .thenReturn(authResponse);

        mockMvc.perform(put("/api/auth/change-password")
                        .with(jwt().jwt(token -> token.subject("user@example.com").claim("id", "1").claim("role", "USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message", is("Password updated successfully")));
    }

    @Test
    @DisplayName("PUT /api/auth/change-password - Debería devolver 400 si contraseña actual es incorrecta")
    void changePassword_withInvalidCurrentPassword_shouldReturnBadRequest() throws Exception {
        ChangePasswordRequest changeRequest = new ChangePasswordRequest("wrongOldPassword", "newPassword");
        AuthDTO errorResponse = new AuthDTO(null, "Contraseña actual incorrecta");
        when(userService.changePassword(eq(changeRequest), any(Authentication.class)))
                .thenReturn(errorResponse);

        mockMvc.perform(put("/api/auth/change-password")
                        .with(jwt().jwt(token -> token.subject("user@example.com").claim("id", "1").claim("role", "USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", is("Contraseña actual incorrecta")));
    }

    @Test
    @DisplayName("PUT /api/auth/change-password - Debería devolver 401 si no está autenticado")
    void changePassword_notAuthenticated_shouldReturnUnauthorized() throws Exception {
        ChangePasswordRequest changeRequest = new ChangePasswordRequest("oldPassword", "newPassword");
        String errorMessage = "Usuario no autenticado o token inválido.";

        mockMvc.perform(put("/api/auth/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", is(errorMessage)));
    }

    @Test
    @DisplayName("GET /api/auth/validate/{token} - Debería validar usuario con token válido")
    void confirmUser_withValidToken_shouldValidateUser() throws Exception {
        String confirmationToken = "valid.confirmation.token";
        Long userIdFromToken = 123L;

        when(jwtUtils.extractUsername(eq(confirmationToken))).thenReturn(String.valueOf(userIdFromToken));
        doNothing().when(adminService).validateUser(eq(userIdFromToken));

        mockMvc.perform(get("/api/auth/validate/" + confirmationToken))
                .andExpect(status().isOk())
                .andExpect(content().string(Constants.CONFIRM));
    }

    @Test
    @DisplayName("GET /api/auth/validate/{token} - Debería devolver error si token es inválido (manejado por servicio)")
    void confirmUser_withInvalidToken_shouldReturnError() throws Exception {
        String invalidToken = "invalid.token";
        String errorMessage = "Token inválido o expirado";

        when(jwtUtils.extractUsername(eq(invalidToken)))
                .thenThrow(new UserException("Token inválido o expirado", HttpStatus.BAD_REQUEST));

        mockMvc.perform(get("/api/auth/validate/" + invalidToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", is(errorMessage)));
    }
}
