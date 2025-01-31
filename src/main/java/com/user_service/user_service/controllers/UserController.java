package com.user_service.user_service.controllers;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.dtos.UpdateUserRecord;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.dtos.UserRecord;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.exceptions.UserNotFoundException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private AdminService adminService;

    @Autowired
    private JwtUtils jwtUtils;


    @GetMapping()
    public ResponseEntity<UserRecord> getUserById(HttpServletRequest request) throws UserException, UserNotFoundException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        Long id = userService.getUserIdByEmail(email).getBody();
        return adminService.getUserById(id);
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
    @PutMapping()
    public ResponseEntity<UserRecord> updateUser(@RequestBody UpdateUserRecord updateUserRecord, HttpServletRequest request) throws UserException, UserNotFoundException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        Long id = userService.getUserIdByEmail(email).getBody();

        return userService.updateUser(id, updateUserRecord);
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
    @DeleteMapping()
    public ResponseEntity<Void> deleteUserById(HttpServletRequest request) throws UserNotFoundException, UserException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        ResponseEntity<Long> id = userService.getUserIdByEmail(email);
        userService.deleteUserById(id.getBody());
        return ResponseEntity.noContent().build();
    }


    @GetMapping("/private/email/{email}")
    public ResponseEntity<Long> getUserIdByEmail(@PathVariable String email) throws UserNotFoundException {
        Long userId = userService.getUserIdByEmail(email).getBody();
        return ResponseEntity.ok(userId);
    }
}
