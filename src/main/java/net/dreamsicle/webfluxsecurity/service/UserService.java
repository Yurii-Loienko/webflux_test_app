package net.dreamsicle.webfluxsecurity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.dreamsicle.webfluxsecurity.entity.UserEntity;
import net.dreamsicle.webfluxsecurity.entity.UserRole;
import net.dreamsicle.webfluxsecurity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Mono<UserEntity> register(UserEntity user) {
        return userRepository.save(
              user.toBuilder()
                    .password(passwordEncoder.encode(user.getPassword()))
                    .role(UserRole.USER)
                    .enabled(true)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build()
        ).doOnSuccess(userCreated -> log.info("IN register user - user: {} created", userCreated));
    }

    public Mono<UserEntity> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public Mono<UserEntity> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
