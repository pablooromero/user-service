package com.user_service.user_service.controllers;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.dtos.UpdateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Users", description = "User Controller")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    private final AdminService adminService;

    private final JwtUtils jwtUtils;

    @Operation(summary = "Get authenticated user's information")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User retrieved successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized",
                    content = @Content),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content)
    })
    @GetMapping()
    public ResponseEntity<UserDTO> getUserById(HttpServletRequest request) throws UserException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        Long id = userService.getUserIdByEmail(email).getBody();

        return adminService.getUserById(id);
    }


    @Operation(summary = "Update authenticated user's information")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User updated successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input",
                    content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthorized",
                    content = @Content),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content)
    })
    @PutMapping()
    public ResponseEntity<UserDTO> updateUser(@RequestBody UpdateUserRequest updateUserRequest, HttpServletRequest request) throws UserException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        Long id = userService.getUserIdByEmail(email).getBody();

        return userService.updateUser(id, updateUserRequest);
    }


    @Operation(summary = "Delete authenticated user's account")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User deleted successfully",
                    content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthorized",
                    content = @Content),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content)
    })
    @DeleteMapping()
    public ResponseEntity<Void> deleteUserById(HttpServletRequest request) throws UserException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        ResponseEntity<Long> id = userService.getUserIdByEmail(email);
        userService.deleteUserById(id.getBody());

        return ResponseEntity.ok().build();
    }


    @Operation(summary = "Get user ID by email (private endpoint)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User ID retrieved successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = Long.class))),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content)
    })
    @GetMapping("/private/email/{email}")
    public ResponseEntity<Long> getUserIdByEmail(@PathVariable String email) throws UserException {
        Long userId = userService.getUserIdByEmail(email).getBody();
        return ResponseEntity.ok(userId);
    }
}
