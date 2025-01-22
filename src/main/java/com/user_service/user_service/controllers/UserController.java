package com.user_service.user_service.controllers;

import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.exceptions.IllegalAttributeException;
import com.user_service.user_service.exceptions.UserNotFoundException;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("users")
public class UserController {

    @Autowired
    private UserService userService;

    @Operation(summary = "Get all users", description = "Retrieve a list of all users")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successful retrieval of users",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UserDTO.class),
                            examples = @ExampleObject(value = "[{\"id\": 1, \"username\": \"user1\", \"email\": \"user1@example.com\"}]")
                    )
            )
    })
    @GetMapping
    public ResponseEntity<List<UserEntity>> getAllUsers() {
        return userService.getAllUsers();
    }


    @Operation(summary = "Create a new user", description = "Create a new user and associate the details")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User user created successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))
            ),
            @ApiResponse(responseCode = "400", description = "Validation errors",
                    content = @Content(mediaType = "application/json",
                            examples = @ExampleObject(value = "Email format is invalid")
                    )
            ),
            @ApiResponse(responseCode = "409", description = "Email already in use",
                    content = @Content(mediaType = "application/json",
                            examples = @ExampleObject(value = "Email is already in use")
                    )
            )
    })
    @PostMapping
    public ResponseEntity<UserDTO> createUser(@RequestBody UserDTO userDTO) throws IllegalAttributeException {
        return userService.createUser(userDTO);
    }


    @Operation(summary = "Update an existing user", description = "Update an existing user's details by their ID")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User updated successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserDTO.class))
            ),
            @ApiResponse(responseCode = "400", description = "Validation errors",
                    content = @Content(mediaType = "application/json",
                            examples = @ExampleObject(value = "Username must be at least 3 characters long")
                    )
            ),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(mediaType = "application/json",
                            examples = @ExampleObject(value = "User not found with ID: 1")
                    )
            )
    })
    @PutMapping
    public ResponseEntity<UserDTO> updateUser(@RequestBody UserDTO userDTO) throws UserNotFoundException, IllegalAttributeException {
        return userService.updateUser(userDTO);
    }


    @Operation(summary = "Delete a user", description = "Delete an existing user by their ID")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "User deleted successfully"),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(mediaType = "application/json",
                            examples = @ExampleObject(value = "User not found with ID: 1")
                    )
            )
    })
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) throws UserNotFoundException {
        return userService.deleteUser(id);
    }


    @Operation(summary = "Get all roles", description = "Retrieve a list of all roles")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successful retrieval of roles")
    })
    @GetMapping("/roles")
    public ResponseEntity<RoleType[]> getAllRoles() {
        return ResponseEntity.ok(RoleType.values());
    }
}
