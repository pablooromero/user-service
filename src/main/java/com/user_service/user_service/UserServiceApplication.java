package com.user_service.user_service;
import com.user_service.user_service.enums.AuthProvider;
import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.enums.UserStatus;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
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

	@Bean
	public CommandLineRunner createAdminUser(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		return (args) -> {
			String adminEmail = "test@example.com";
			if(userRepository.existsByEmail(adminEmail)) {
				System.out.println("User already exists with email " + adminEmail);
				return;
			}

			UserEntity admin = new  UserEntity(
					"Admin",
					"Test",
					"test@example.com",
					passwordEncoder.encode("Test12345"),
					RoleType.ADMIN, UserStatus.ACTIVE,
					AuthProvider.LOCAL);
			userRepository.save(admin);
		};
	}
}
