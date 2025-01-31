package com.user_service.user_service.controllers;

import com.user_service.user_service.dtos.NewUserRecord;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.dtos.UserRecord;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
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

import java.util.Set;

@RestController
@RequestMapping("api/admins")
public class AdminController {

    @Autowired
    private AdminService adminService;

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
    @GetMapping("/users/all")
    public ResponseEntity<Set<UserRecord>> getAllUsers() {
        return adminService.getAllUsers();
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<UserRecord> getUserById(@PathVariable Long id) throws UserException {
        return adminService.getUserById(id);
    }

    @PostMapping("/admin")
    public ResponseEntity<UserRecord> createAdmin(@RequestBody NewUserRecord newUserRecord) throws UserException {
        return adminService.createAdmin(newUserRecord);
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
    @DeleteMapping("/users/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) throws UserException {
        return adminService.deleteUserById(id);
    }


    @Operation(summary = "Get all roles", description = "Retrieve a list of all roles")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successful retrieval of roles")
    })
    @GetMapping("/admin/roles")
    public ResponseEntity<RoleType[]> getAllRoles() {
        return ResponseEntity.ok(RoleType.values());
    }
}
