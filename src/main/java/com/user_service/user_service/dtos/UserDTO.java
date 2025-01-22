package com.user_service.user_service.dtos;

import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.models.UserEntity;

public class UserDTO {

    private Long id;
    private String username;
    private String email;
    private String password;
    private RoleType role;

    public UserDTO() {}

    public UserDTO(UserEntity userEntity) {
        id = userEntity.getId();
        username = userEntity.getUsername();
        email = userEntity.getEmail();
        password = userEntity.getPassword();
        role = userEntity.getRole();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public RoleType getRole() {
        return role;
    }

    public void setRole(RoleType role) {
        this.role = role;
    }
}
