package com.user_service.user_service.controllers;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.dtos.UpdateUserRequest;
import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private AdminService adminService;

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping()
    public ResponseEntity<UserDTO> getUserById(HttpServletRequest request) throws UserException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        Long id = userService.getUserIdByEmail(email).getBody();

        return adminService.getUserById(id);
    }

    @PutMapping()
    public ResponseEntity<UserDTO> updateUser(@RequestBody UpdateUserRequest updateUserRequest, HttpServletRequest request) throws UserException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        Long id = userService.getUserIdByEmail(email).getBody();

        return userService.updateUser(id, updateUserRequest);
    }

    @DeleteMapping()
    public ResponseEntity<Void> deleteUserById(HttpServletRequest request) throws UserException {
        String email = jwtUtils.getEmailFromToken(request.getHeader("Authorization"));
        ResponseEntity<Long> id = userService.getUserIdByEmail(email);
        userService.deleteUserById(id.getBody());

        return ResponseEntity.ok().build();
    }

    @GetMapping("/private/email/{email}")
    public ResponseEntity<Long> getUserIdByEmail(@PathVariable String email) throws UserException {
        Long userId = userService.getUserIdByEmail(email).getBody();
        return ResponseEntity.ok(userId);
    }
}
