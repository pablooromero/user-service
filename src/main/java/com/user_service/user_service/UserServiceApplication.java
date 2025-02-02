package com.user_service.user_service;

import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.Status;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class UserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceApplication.class, args);
	}

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Bean
	public CommandLineRunner init(UserRepository userRepository) {
		return args -> {

			UserEntity admin = new UserEntity();
			admin.setUsername("admin");
			admin.setPassword(passwordEncoder.encode("adminpassword"));
			admin.setEmail("admin@admin.com");
			admin.setRole(RoleType.ADMIN);
			admin.setStatus(Status.ACTIVE);
			userRepository.save(admin);
		};
	}
}
