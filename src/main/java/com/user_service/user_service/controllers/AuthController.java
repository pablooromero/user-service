package com.user_service.user_service.controllers;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.AuthService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Tag(name = "Auth", description = "Auth Controller")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    private final UserService userService;

    private final AdminService adminService;

    private final JwtUtils jwtUtils;

    @Operation(summary = "Login with email and password", description = "Authenticates a user and returns a JWT token.")
    @ApiResponse(responseCode = "200", description = "Login successful, returns JWT token", content = @Content(mediaType = "application/json", schema = @Schema(example = "{\"token\": \"<jwt-token>\"}")))
    @ApiResponse(responseCode = "401", description = "Invalid credentials", content = @Content)
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginUserDTO loginUserDTO) {
        return authService.loginUser(loginUserDTO);
    }


    @Operation(summary = "Register a new user", description = "Registers a new user in the system.")
    @ApiResponse(responseCode = "200", description = "User registered successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class)))
    @ApiResponse(responseCode = "400", description = "Invalid input data", content = @Content)
    @ApiResponse(responseCode = "409", description = "User already exists", content = @Content)
    @PostMapping("/register")
    public ResponseEntity<UserDTO> registerUser(@RequestBody CreateUserRequest createUserRequest) {
        UserDTO user = authService.createUser(createUserRequest);
        return ResponseEntity.ok(user);
    }


    @Operation(summary = "Login with Google", description = "Redirects the user to the Google OAuth2 login page.")
    @ApiResponse(responseCode = "302", description = "Redirect to Google OAuth2 authorization endpoint")
    @GetMapping("/google-login")
    public void googleLogin(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/google");
    }


    @Operation(summary = "Change password", description = "Changes the password of the authenticated user.")
    @ApiResponse(responseCode = "200", description = "Password changed successfully", content = @Content(schema = @Schema(implementation = AuthDTO.class)))
    @ApiResponse(responseCode = "400", description = "Invalid current password or bad input", content = @Content)
    @PutMapping("/change-password")
    public ResponseEntity<AuthDTO> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof Jwt)) {
            throw new UserException("Usuario no autenticado o token inválido.", HttpStatus.UNAUTHORIZED);
        }
        AuthDTO response = userService.changePassword(changePasswordRequest, authentication);
        if(response.message().equals("Password updated successfully")){
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }


    @Operation(summary = "Validate user account", description = "Validates a user using a token sent to their email.")
    @ApiResponse(responseCode = "200", description = "User validated successfully")
    @ApiResponse(responseCode = "400", description = "Invalid or expired token")
    @GetMapping("/validate/{confirmationToken}")
    public ResponseEntity<String> confirmUser(@PathVariable String confirmationToken) {
        Long id = Long.parseLong(jwtUtils.extractUsername(confirmationToken));
        adminService.validateUser(id);

        return ResponseEntity.ok(Constants.CONFIRM);
    }

}
