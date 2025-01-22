package com.user_service.user_service;

import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.models.UserEntity;
import com.user_service.user_service.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class UserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceApplication.class, args);
	}


	@Bean
	public CommandLineRunner init(UserRepository userRepository) {
		return args -> {
			UserEntity user = new UserEntity();
			user.setUsername("testnombre");
			user.setPassword("testpassword");
			user.setEmail("test@test.com");
			user.setRole(RoleType.USER);

			userRepository.save(user);
		};
	}
}
