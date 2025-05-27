package com.user_service.user_service.repositories;

import com.user_service.user_service.enums.RoleType;
import com.user_service.user_service.models.UserEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    private UserEntity user1;
    private UserEntity user2;


    @BeforeEach
    void setUp() {
        user1 = new UserEntity();
        user1.setEmail("test1@example.com");
        user1.setPassword("password123");
        user1.setName("Test");
        user1.setLastName("User1");
        user1.setRole(RoleType.USER);

        user2 = new UserEntity();
        user2.setEmail("admin@example.com");
        user2.setPassword("adminpass");
        user2.setName("Admin");
        user2.setLastName("User2");
        user2.setRole(RoleType.ADMIN);
    }

    @Test
    @DisplayName("findByEmail - Debería encontrar un usuario por su email si existe")
    void findByEmail_whenUserExists_shouldReturnUser() {
        entityManager.persistAndFlush(user1);

        Optional<UserEntity> foundUserOptional = userRepository.findByEmail("test1@example.com");

        assertTrue(foundUserOptional.isPresent());
        UserEntity foundUser = foundUserOptional.get();
        assertThat(foundUser.getEmail()).isEqualTo("test1@example.com");
        assertThat(foundUser.getName()).isEqualTo("Test");
    }

    @Test
    @DisplayName("findByEmail - Debería devolver Optional.empty si el email no existe")
    void findByEmail_whenUserDoesNotExist_shouldReturnEmptyOptional() {
        entityManager.persistAndFlush(user1);

        Optional<UserEntity> foundUserOptional = userRepository.findByEmail("nonexistent@example.com");

        assertFalse(foundUserOptional.isPresent());
    }

    @Test
    @DisplayName("existsByEmail - Debería devolver true si el email existe")
    void existsByEmail_whenEmailExists_shouldReturnTrue() {
        entityManager.persistAndFlush(user1);

        boolean exists = userRepository.existsByEmail("test1@example.com");

        assertTrue(exists);
    }

    @Test
    @DisplayName("existsByEmail - Debería devolver false si el email no existe")
    void existsByEmail_whenEmailDoesNotExist_shouldReturnFalse() {
        entityManager.persistAndFlush(user1);

        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        assertFalse(exists);
    }

    @Test
    @DisplayName("Guardar un UserEntity debería asignarle un ID")
    void saveUser_shouldAssignId() {

        UserEntity savedUser = userRepository.save(user1);
        entityManager.flush();

        assertNotNull(savedUser.getId());
        assertThat(savedUser.getId()).isPositive();
        assertThat(savedUser.getEmail()).isEqualTo("test1@example.com");
    }

    @Test
    @DisplayName("No debería encontrar un usuario después de ser eliminado")
    void deleteUser_shouldRemoveUserFromDatabase() {
        UserEntity savedUser = entityManager.persistAndFlush(user1);
        Long userId = savedUser.getId();
        assertTrue(userRepository.existsById(userId), "El usuario debería existir antes de eliminarlo");

        userRepository.deleteById(userId);
        entityManager.flush();
        entityManager.clear();

        Optional<UserEntity> foundAfterDelete = userRepository.findById(userId);
        assertFalse(foundAfterDelete.isPresent(), "El usuario no debería ser encontrado después de eliminarlo");
    }
}