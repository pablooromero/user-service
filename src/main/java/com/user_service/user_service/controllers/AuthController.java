package com.user_service.user_service.controllers;

import com.user_service.user_service.config.JwtUtils;
import com.user_service.user_service.dtos.*;
import com.user_service.user_service.exceptions.UserException;
import com.user_service.user_service.services.AdminService;
import com.user_service.user_service.services.AuthService;
import com.user_service.user_service.services.UserService;
import com.user_service.user_service.utils.Constants;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    private final UserService userService;

    private final AdminService adminService;

    private final JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginUserDTO loginUserDTO) throws UserException {
        return authService.loginUser(loginUserDTO);
    }

    @PostMapping("/register")
    public ResponseEntity<UserDTO> registerUser(@RequestBody CreateUserRequest createUserRequest) throws UserException {
        UserDTO user = authService.createUser(createUserRequest);
        return ResponseEntity.ok(user);
    }

    @PutMapping("/change-password")
    public ResponseEntity<AuthDTO> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest, Authentication authentication) throws UserException {
        AuthDTO response = userService.changePassword(changePasswordRequest, authentication);
        if(response.message().equals("Password updated successfully")){
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/validate/{confirmationToken}")
    public ResponseEntity<String> confirmUser(@PathVariable String confirmationToken) throws UserException {
        Long id = Long.parseLong(jwtUtils.extractUsername(confirmationToken));
        adminService.validateUser(id);

        return ResponseEntity.ok(Constants.CONFIRM);
    }

}
