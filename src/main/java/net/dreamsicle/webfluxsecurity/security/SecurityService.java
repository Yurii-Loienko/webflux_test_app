package net.dreamsicle.webfluxsecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import net.dreamsicle.webfluxsecurity.entity.UserEntity;
import net.dreamsicle.webfluxsecurity.exception.AuthException;
import net.dreamsicle.webfluxsecurity.repository.UserRepository;
import net.dreamsicle.webfluxsecurity.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class SecurityService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Integer expirationInSeconds;
    @Value("${jwt.issuer}")
    private String issuer;

    private TokenDetails generateToken(UserEntity user) {
        Map<String, Object> claims = Map.of(
              "role", user.getRole(),
              "username", user.getUsername()
        );

        return generateToken(claims, user.getId().toString());
    }

    private TokenDetails generateToken(Map<String, Object> claims, String subject) {
        return generateToken(new Date(System.currentTimeMillis() + expirationInSeconds * 1000), claims, subject);
    }

    private TokenDetails generateToken(Date expirationDate, Map<String, Object> claims, String subject) {

        var creationDate = new Date();
        var token = Jwts.builder()
              .setClaims(claims)
              .setSubject(subject)
              .setIssuer(issuer)
              .setIssuedAt(creationDate)
              .setExpiration(expirationDate)
              .setId(UUID.randomUUID().toString())
              .signWith(SignatureAlgorithm.HS512, Base64.getEncoder().encodeToString(secret.getBytes()))
              .compact();

        return TokenDetails.builder()
              .token(token)
              .issuedAt(creationDate)
              .expiresAt(expirationDate)
              .build();
    }

    public Mono<TokenDetails> authenticate(String username, String password) {
        return userService.getUserByUsername(username)
              .flatMap(user -> {
                  if (!user.isEnabled()) {
                      return Mono.error(new AuthException("User is disabled", "USER_ACCOUNT_DISABLED"));
                  }

                  if (!passwordEncoder.matches(password, user.getPassword())) {
                      return Mono.error(new AuthException("Invalid credentials", "INVALID_CREDENTIALS"));
                  }

                  return Mono.just(generateToken(user).toBuilder()
                        .userId(user.getId())
                        .build());
              })
              .switchIfEmpty(Mono.error(new AuthException("User not found", "USER_NOT_FOUND")));
    }
}
