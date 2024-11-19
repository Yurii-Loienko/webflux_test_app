package net.dreamsicle.webfluxsecurity.config;

import lombok.extern.slf4j.Slf4j;
import net.dreamsicle.webfluxsecurity.security.AuthenticationManager;
import net.dreamsicle.webfluxsecurity.security.BearerTokenServerAuthenticationConverter;
import net.dreamsicle.webfluxsecurity.security.JwtHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

    @Value("${jwt.secret}")
    private String secret;

    private final String[] publicRoutes = {"/api/v1/auth/register", "/api/v1/auth/login"};

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, AuthenticationManager authenticationManager) {
        return http
              .csrf(ServerHttpSecurity.CsrfSpec::disable)
              .authorizeExchange(exchange -> exchange
                    .pathMatchers(HttpMethod.OPTIONS).permitAll()
                    .pathMatchers(publicRoutes).permitAll()
                    .anyExchange().authenticated()
              )
              .exceptionHandling(ex -> ex
                    .authenticationEntryPoint((exchange, _) -> {
                        log.error("Unauthorized error: {}", exchange.getResponse());
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return Mono.empty();
                    })
                    .accessDeniedHandler((exchange, _) -> {
                        log.error("Access denied error: {}", exchange.getResponse());
                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        return Mono.empty();
                    })
              )
              .addFilterAt(bearerAuthenticationFilter(authenticationManager), SecurityWebFiltersOrder.AUTHENTICATION)
              .build();
    }

    private AuthenticationWebFilter bearerAuthenticationFilter(AuthenticationManager authenticationManager) {
        var bearerAuthenticationFilter = new AuthenticationWebFilter(authenticationManager);
        bearerAuthenticationFilter.setServerAuthenticationConverter(
              new BearerTokenServerAuthenticationConverter(new JwtHandler(secret))
        );
        bearerAuthenticationFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/**"));
        return bearerAuthenticationFilter;
    }
}
