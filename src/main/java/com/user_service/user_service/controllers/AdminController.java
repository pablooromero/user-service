package com.user_service.user_service.controllers;

import com.user_service.user_service.dtos.UserDTO;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/admins")
public class AdminController {
    private final AdminService adminService;

    @GetMapping("/users")
    public ResponseEntity <Set<UserDTO>> getAllUsers() {
        return adminService.getAllUsers();
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) throws UserException {
        return adminService.getUserById(id);
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<String> deleteUserById(@PathVariable Long id) throws UserException {
        return adminService.deleteUserById(id);
    }

}
