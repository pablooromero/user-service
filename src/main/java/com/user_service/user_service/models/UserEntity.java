package com.user_service.user_service.models;

import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column
    private String lastName;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = true)
    private String password;

    @Column
    private RoleType role;

    @Column
    private UserStatus status =  UserStatus.PENDING;

    @Column
    private AuthProvider authProvider;

    public UserEntity(String name, String lastName, String email, String password, RoleType role, UserStatus status,  AuthProvider authProvider) {
        this.name = name;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.role = role;
        this.status = status;
        this.authProvider = authProvider;
    }
}
