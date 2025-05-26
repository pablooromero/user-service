package com.user_service.user_service.services;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.config.RabbitMQConfig;
import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.EmailEvent;
import com.user_service.user_service.dtos.LoginUserDTO;
import com.user_service.user_service.dtos.RegisterUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import com.user_service.user_service.services.implementations.AuthServiceImplementation;
import com.user_service.user_service.utils.Constants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;


import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplementationTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserService userService;

    @Mock
    private AdminService adminService;

    @Mock
    private RabbitTemplate rabbitTemplate;

    @InjectMocks
    private AuthServiceImplementation authService;

    private LoginUserDTO loginUserDTO;
    private CreateUserRequest createUserRequest;
    private UserEntity testUserEntity;
    private RegisterUserRequest registerUserRequestActive;
    private RegisterUserRequest registerUserRequestPending;

    @BeforeEach
    void setUp() {
        loginUserDTO = new LoginUserDTO("test@example.com", "password");
        createUserRequest = new CreateUserRequest("Test", "User", "new@example.com", "password123");

        testUserEntity = new UserEntity(1L, "Test", "User", "test@example.com", "encodedPassword", RoleType.USER, UserStatus.ACTIVE, AuthProvider.LOCAL);

        registerUserRequestActive = new RegisterUserRequest(1L, "Test", "User", "test@example.com", UserStatus.ACTIVE, RoleType.USER);
        registerUserRequestPending = new RegisterUserRequest(2L, "Pending", "User", "pending@example.com", UserStatus.PENDING, RoleType.USER);
    }

    @Test
    @DisplayName("loginUser - Con credenciales válidas y usuario ACTIVO, debería devolver JWT")
    void loginUser_validCredentialsActiveUser_shouldReturnJwt() throws UserException {
        Authentication mockAuthentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mockAuthentication);
        when(userService.getUserByEmail(loginUserDTO.email())).thenReturn(registerUserRequestActive);
        when(jwtUtils.generateToken(registerUserRequestActive.email(), registerUserRequestActive.id(), registerUserRequestActive.role().toString()))
                .thenReturn("mocked.jwt.token");

        ResponseEntity<String> response = authService.loginUser(loginUserDTO);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("mocked.jwt.token", response.getBody());
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    @DisplayName("loginUser - Con credenciales inválidas, debería lanzar UserException UNAUTHORIZED")
    void loginUser_invalidCredentials_shouldThrowUserException() throws UserException {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Credenciales inválidas simuladas"));

        UserException exception = assertThrows(UserException.class, () -> {
            authService.loginUser(loginUserDTO);
        });
        assertEquals(Constants.INV_CRED, exception.getMessage());
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getHttpStatus());
    }

    @Test
    @DisplayName("loginUser - Con credenciales válidas pero usuario PENDING, debería lanzar UserException UNAUTHORIZED")
    void loginUser_validCredentialsPendingUser_shouldThrowUserException() throws UserException {
        Authentication mockAuthentication = mock(Authentication.class);
        LoginUserDTO pendingUserLoginDTO = new LoginUserDTO("pending@example.com", "password");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mockAuthentication);
        when(userService.getUserByEmail(pendingUserLoginDTO.email())).thenReturn(registerUserRequestPending);

        UserException exception = assertThrows(UserException.class, () -> {
            authService.loginUser(pendingUserLoginDTO);
        });
        assertEquals(Constants.NOT_ACTIVE, exception.getMessage());
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getHttpStatus());
        verify(jwtUtils, never()).generateToken(anyString(), anyLong(), anyString());
    }

    @Test
    @DisplayName("loginUser - Cuando userService.getUserByEmail lanza UserException, debería propagar esa UserException")
    void loginUser_userServiceThrowsException_shouldRethrowUserException() throws UserException {
        Authentication mockAuthentication = mock(Authentication.class);
        String originalErrorMessage = "Error interno del servicio de usuario";
        HttpStatus originalStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        UserException originalUserServiceException = new UserException(originalErrorMessage, originalStatus);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mockAuthentication);
        when(userService.getUserByEmail(loginUserDTO.email()))
                .thenThrow(originalUserServiceException);

        UserException actualException = assertThrows(UserException.class, () -> {
            authService.loginUser(loginUserDTO);
        });

        assertEquals(originalErrorMessage, actualException.getMessage());
        assertEquals(originalStatus, actualException.getHttpStatus());
    }


    @Test
    @DisplayName("createUser - Con datos válidos, debería crear usuario, enviar email y devolver UserDTO")
    void createUser_validData_shouldCreateUserSendEmailAndReturnDTO() throws UserException {
        doNothing().when(adminService).validatePassword(createUserRequest.password());
        doNothing().when(adminService).validateEmail(createUserRequest.email());
        when(passwordEncoder.encode(createUserRequest.password())).thenReturn("encodedPasswordForNewUser");

        UserEntity userToSave = new UserEntity(
                createUserRequest.name(), createUserRequest.lastName(), createUserRequest.email(),
                "encodedPasswordForNewUser", RoleType.USER, UserStatus.PENDING, AuthProvider.LOCAL
        );
        UserEntity savedUser = new UserEntity(
                100L,
                createUserRequest.name(), createUserRequest.lastName(), createUserRequest.email(),
                "encodedPasswordForNewUser", RoleType.USER, UserStatus.PENDING, AuthProvider.LOCAL
        );
        when(userRepository.save(any(UserEntity.class))).thenReturn(savedUser);
        when(jwtUtils.generateRegisterToken(eq(100L), anyLong())).thenReturn("registration.jwt.token");

        UserDTO resultDTO = authService.createUser(createUserRequest);

        assertNotNull(resultDTO);
        assertEquals(createUserRequest.email(), resultDTO.email());
        assertEquals(RoleType.USER, resultDTO.role());
        assertEquals(UserStatus.PENDING, resultDTO.status());
        assertNotNull(resultDTO.id());

        verify(adminService, times(1)).validatePassword(createUserRequest.password());
        verify(adminService, times(1)).validateEmail(createUserRequest.email());
        verify(passwordEncoder, times(1)).encode(createUserRequest.password());

        ArgumentCaptor<UserEntity> userEntityCaptor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository, times(1)).save(userEntityCaptor.capture());
        assertEquals(UserStatus.PENDING, userEntityCaptor.getValue().getStatus());
        assertEquals(AuthProvider.LOCAL, userEntityCaptor.getValue().getAuthProvider());

        verify(jwtUtils, times(1)).generateRegisterToken(eq(savedUser.getId()), anyLong());
        ArgumentCaptor<EmailEvent> emailEventCaptor = ArgumentCaptor.forClass(EmailEvent.class);
        verify(rabbitTemplate, times(1)).convertAndSend(
                eq(RabbitMQConfig.EXCHANGE_NAME),
                eq("user.email"),
                emailEventCaptor.capture()
        );
        assertEquals(createUserRequest.email(), emailEventCaptor.getValue().to());
        assertTrue(emailEventCaptor.getValue().body().contains("http://localhost:8080/api/auth/validate/registration.jwt.token"));
    }

    @Test
    @DisplayName("createUser - Cuando validatePassword falla, debería lanzar UserException")
    void createUser_whenValidatePasswordFails_shouldThrowUserException() throws UserException {
        doThrow(new UserException(Constants.EMPTY_PASS, HttpStatus.BAD_REQUEST))
                .when(adminService).validatePassword(createUserRequest.password());

        UserException exception = assertThrows(UserException.class, () -> {
            authService.createUser(createUserRequest);
        });
        assertEquals(Constants.EMPTY_PASS, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
        verify(userRepository, never()).save(any(UserEntity.class));
        verify(rabbitTemplate, never()).convertAndSend(anyString(), anyString(), any(EmailEvent.class));
    }

    @Test
    @DisplayName("createUser - Cuando validateEmail falla, debería lanzar UserException")
    void createUser_whenValidateEmailFails_shouldThrowUserException() throws UserException {
        doNothing().when(adminService).validatePassword(createUserRequest.password());
        doThrow(new UserException(Constants.EXIST_EMAIL, HttpStatus.BAD_REQUEST))
                .when(adminService).validateEmail(createUserRequest.email());

        UserException exception = assertThrows(UserException.class, () -> {
            authService.createUser(createUserRequest);
        });
        assertEquals(Constants.EXIST_EMAIL, exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getHttpStatus());
        verify(userRepository, never()).save(any(UserEntity.class));
        verify(rabbitTemplate, never()).convertAndSend(anyString(), anyString(), any(EmailEvent.class));
    }

    @Test
    @DisplayName("createUser - Cuando falla el envío a RabbitMQ, el usuario igual se crea")
    void createUser_whenRabbitMqFails_userStillCreatedButLogsError() throws UserException {
        doNothing().when(adminService).validatePassword(createUserRequest.password());
        doNothing().when(adminService).validateEmail(createUserRequest.email());
        when(passwordEncoder.encode(createUserRequest.password())).thenReturn("encodedPasswordForNewUser");
        UserEntity savedUser = new UserEntity(100L, createUserRequest.name(), createUserRequest.lastName(), createUserRequest.email(), "encodedPasswordForNewUser", RoleType.USER, UserStatus.PENDING, AuthProvider.LOCAL);
        when(userRepository.save(any(UserEntity.class))).thenReturn(savedUser);
        when(jwtUtils.generateRegisterToken(eq(100L), anyLong())).thenReturn("registration.jwt.token");

        doThrow(new AmqpException("Simulated RabbitMQ send failure"))
                .when(rabbitTemplate).convertAndSend(anyString(), anyString(), any(EmailEvent.class));

        UserDTO resultDTO = authService.createUser(createUserRequest);


        assertNotNull(resultDTO);
        assertEquals(createUserRequest.email(), resultDTO.email());
        verify(userRepository, times(1)).save(any(UserEntity.class));
        verify(rabbitTemplate, times(1)).convertAndSend(anyString(), anyString(), any(EmailEvent.class));
    }
}