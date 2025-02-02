package com.user_service.user_service.controllers;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.exceptions.UserNotFoundException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.AuthService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserService userService;

    @Autowired
    private AdminService adminService;

    @Autowired
    private JwtUtils jwtUtils;

    @Operation(summary = "Login user", description = "Authenticate a user and generate a JWT token")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful",
                    content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "401", description = "Invalid email or password",
                    content = @Content(mediaType = "application/json", examples = @ExampleObject(value = "Invalid email or password"))),
            @ApiResponse(responseCode = "500", description = "Internal server error during login",
                    content = @Content(mediaType = "application/json", examples = @ExampleObject(value = "An error occurred during login")))
    })
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginUserRecord loginRequest) throws UserException {
        return authService.loginUser(loginRequest);
    }


    @Operation(summary = "Register user", description = "Create a new user and generate a JWT token")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User registered successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserRecord.class))),
            @ApiResponse(responseCode = "400", description = "Missing or invalid fields",
                    content = @Content(mediaType = "application/json", examples = @ExampleObject(value = "Every field is required."))),
            @ApiResponse(responseCode = "400", description = "Email or username already in use",
                    content = @Content(mediaType = "application/json", examples = @ExampleObject(value = "The email or username is already in use.")))
    })
    @PostMapping("/register")
    public ResponseEntity<UserRecord> createUser(@RequestBody NewUserRecord newUserRecord) throws UserException {
        UserRecord user = authService.createUser(newUserRecord);
        return ResponseEntity.ok(user);
    }

    @Operation(summary = "Change user password", description = "Change the password of the authenticated user")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Password updated successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthResponseDTO.class))
            ),
            @ApiResponse(responseCode = "400", description = "Validation errors",
                    content = @Content(mediaType = "application/json",
                            examples = @ExampleObject(value = "New password must be at least 8 characters long")
                    )
            ),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(mediaType = "application/json",
                            examples = @ExampleObject(value = "User not found with ID: 1")
                    )
            )
    })
    @PutMapping("/change-password")
    public ResponseEntity<AuthResponseDTO> changePassword(@RequestBody ChangePasswordDTO changePasswordDTO, Authentication authentication) throws UserNotFoundException, UserNotFoundException {
        AuthResponseDTO response = userService.changePassword(changePasswordDTO, authentication);
        if (response.getMessage().equals("Password updated successfully")) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/register/{confirmationToken}")
    public ResponseEntity<String> confirmUser(@PathVariable String confirmationToken) throws UserException {
        Long id = Long.parseLong(jwtUtils.extractUsername(confirmationToken));
        adminService.validateUser(id);
        return ResponseEntity.ok(Constants.CONFIRM);
    }

}
