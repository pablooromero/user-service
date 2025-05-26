package com.user_service.user_service.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.config.SecurityConfig;
import com.user_service.user_service.dtos.CreateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.exceptions.ExceptionHandlers;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.OAuthService;
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
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashSet;
import java.util.Set;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@WebMvcTest(AdminController.class)
@Import({SecurityConfig.class, ExceptionHandlers.class})
public class AdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AdminService adminService;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private OAuthService  oAuthService;

    @MockBean
    private ClientRegistrationRepository  clientRegistrationRepository;

    private UserDTO adminUserDTO;
    private UserDTO regularUserDTO;
    private Set<UserDTO> userDTOSet;

    @BeforeEach
    void setUp() {
        adminUserDTO = new UserDTO(1L, "Admin", "User", "admin@example.com", RoleType.ADMIN, UserStatus.ACTIVE);
        regularUserDTO = new UserDTO(2L, "Regular", "User", "user@example.com", RoleType.USER, UserStatus.ACTIVE);

        userDTOSet = new HashSet<>();
        userDTOSet.add(adminUserDTO);
        userDTOSet.add(regularUserDTO);
    }

    @Test
    @DisplayName("GET /api/admins/users - Debería devolver todos los usuarios si es ADMIN")
    void getAllUsers_asAdmin_shouldReturnAllUsers() throws Exception {
        when(adminService.getAllUsers()).thenReturn(ResponseEntity.ok(userDTOSet));

        mockMvc.perform(get("/api/admins/users")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(token -> token.claim("role", "ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[?(@.email == 'admin@example.com')]", hasSize(1)));
    }

    @Test
    @DisplayName("GET /api/admins/users - Debería devolver 403 Forbidden si NO es ADMIN")
    void getAllUsers_asNonAdmin_shouldReturnForbidden() throws Exception {
        mockMvc.perform(get("/api/admins/users")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))
                                .jwt(token -> token.claim("role", "USER"))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /api/admins/users - Debería devolver 401 Unauthorized si no está autenticado")
    void getAllUsers_notAuthenticated_shouldReturnUnauthorized() throws Exception {
        mockMvc.perform(get("/api/admins/users"))
                .andExpect(status().isUnauthorized());
    }


    @Test
    @DisplayName("GET /api/admins/users/{id} - Debería devolver usuario si es ADMIN y existe")
    void getUserById_asAdmin_whenUserExists_shouldReturnUser() throws Exception {
        when(adminService.getUserById(1L)).thenReturn(ResponseEntity.ok(adminUserDTO));

        mockMvc.perform(get("/api/admins/users/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(token -> token.claim("role", "ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(1)))
                .andExpect(jsonPath("$.email", is("admin@example.com")));
    }

    @Test
    @DisplayName("GET /api/admins/users/{id} - Debería devolver 404 si es ADMIN pero usuario no existe")
    void getUserById_asAdmin_whenUserNotExists_shouldReturnNotFound() throws Exception {
        when(adminService.getUserById(99L))
                .thenThrow(new UserException("Usuario no encontrado", HttpStatus.NOT_FOUND));

        mockMvc.perform(get("/api/admins/users/99")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(token -> token.claim("role", "ADMIN"))))
                .andExpect(status().isNotFound())
                .andExpect(content().string("Usuario no encontrado"));
    }


    @Test
    @DisplayName("POST /api/admins - Debería crear admin si es ADMIN")
    void createAdmin_asAdmin_shouldCreateAdmin() throws Exception {
        CreateUserRequest createRequest = new CreateUserRequest("New", "Admin", "newadmin@example.com", "password");
        UserDTO createdAdminDto = new UserDTO(3L, "New", "Admin", "newadmin@example.com", RoleType.ADMIN, UserStatus.ACTIVE);
        when(adminService.createAdmin(any(CreateUserRequest.class)))
                .thenReturn(ResponseEntity.ok(createdAdminDto));

        mockMvc.perform(post("/api/admins")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(token -> token.claim("role", "ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email", is("newadmin@example.com")));
    }

    @Test
    @DisplayName("POST /api/admins - Debería devolver 409 si email ya existe (manejado por servicio)")
    void createAdmin_asAdmin_whenEmailExists_shouldReturnConflict() throws Exception {
        CreateUserRequest createRequest = new CreateUserRequest("Existing", "Admin", "admin@example.com", "password");
        when(adminService.createAdmin(any(CreateUserRequest.class)))
                .thenThrow(new UserException("Email ya existe", HttpStatus.CONFLICT));

        mockMvc.perform(post("/api/admins")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(token -> token.claim("role", "ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createRequest)))
                .andExpect(status().isConflict())
                .andExpect(content().string("Email ya existe"));
    }


    @Test
    @DisplayName("DELETE /api/admins/users/{id} - Debería eliminar usuario si es ADMIN")
    void deleteUserById_asAdmin_shouldDeleteUser() throws Exception {
        when(adminService.deleteUserById(1L))
                .thenReturn(ResponseEntity.ok("Usuario eliminado exitosamente"));

        mockMvc.perform(delete("/api/admins/users/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(token -> token.claim("role", "ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(content().string("Usuario eliminado exitosamente"));
    }

    @Test
    @DisplayName("DELETE /api/admins/users/{id} - Debería devolver 404 si es ADMIN pero usuario no existe")
    void deleteUserById_asAdmin_whenUserNotExists_shouldReturnNotFound() throws Exception {
        when(adminService.deleteUserById(99L))
                .thenThrow(new UserException("Usuario no encontrado para eliminar", HttpStatus.NOT_FOUND));

        mockMvc.perform(delete("/api/admins/users/99")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))
                                .jwt(token -> token.claim("role", "ADMIN"))))
                .andExpect(status().isNotFound())
                .andExpect(content().string("Usuario no encontrado para eliminar"));
    }
}
