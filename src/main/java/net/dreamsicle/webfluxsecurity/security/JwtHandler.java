package net.dreamsicle.webfluxsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import net.dreamsicle.webfluxsecurity.exception.AuthException;
import net.dreamsicle.webfluxsecurity.exception.UnauthorizedException;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.Date;

@RequiredArgsConstructor
public class JwtHandler {

    private final String secret;

    public Mono<VerificationResult> check(String accessToken) {
        return Mono.just(verify(accessToken))
              .onErrorResume(e -> Mono.error(new UnauthorizedException(e.getMessage())));
    }

    private VerificationResult verify(String token) {
        Claims claims = getClaimsFromToken(token);
        final Date expiration = claims.getExpiration();

        if (expiration.before(new Date())) {
            throw new RuntimeException("Token expired");
        }

        return new VerificationResult(claims, token);
    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser()
              .setSigningKey(Base64.getEncoder().encodeToString(secret.getBytes()))
              .parseClaimsJws(token)
              .getBody();
    }

    public record VerificationResult(Claims claims, String token) {
    }

}
