package net.dreamsicle.webfluxsecurity.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

import java.util.List;

public class UserAuthenticationBearer {

    public static Mono<Authentication> create(JwtHandler.VerificationResult verificationResult) {
        var claims = verificationResult.claims();
        var subject = claims.getSubject();

        var role = claims.get("role", String.class);
        var username = claims.get("username", String.class);

        var authorities = List.of(new SimpleGrantedAuthority(role));

        var principalId = Long.parseLong(subject);
        var principal = new CustomPrincipal(principalId, username);
        return Mono
              .justOrEmpty(new UsernamePasswordAuthenticationToken(principal, null, authorities));
    }
}
