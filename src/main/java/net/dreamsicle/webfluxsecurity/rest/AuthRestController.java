package net.dreamsicle.webfluxsecurity.rest;

import lombok.AllArgsConstructor;
import net.dreamsicle.webfluxsecurity.dto.AuthRequestDto;
import net.dreamsicle.webfluxsecurity.dto.AuthResponseDto;
import net.dreamsicle.webfluxsecurity.dto.UserDto;
import net.dreamsicle.webfluxsecurity.mapper.UserMapper;
import net.dreamsicle.webfluxsecurity.security.CustomPrincipal;
import net.dreamsicle.webfluxsecurity.security.SecurityService;
import net.dreamsicle.webfluxsecurity.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthRestController {

    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper mapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto userDto) {
        return userService.register(mapper.map(userDto))
              .map(mapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(AuthRequestDto requestDto) {
        return securityService.authenticate(requestDto.getUsername(), requestDto.getPassword())
              .flatMap(tokenDetails -> Mono.just(AuthResponseDto.builder()
                          .userId(tokenDetails.getUserId())
                          .token(tokenDetails.getToken())
                          .issueAt(tokenDetails.getIssuedAt())
                          .expiresAt(tokenDetails.getExpiresAt())
                    .build()));
    }

    @GetMapping("/info")
    public Mono<UserDto> getUserInfo(Authentication authentication) {
        var principal = (CustomPrincipal) authentication.getPrincipal();
        return userService.getUserById(principal.getId())
              .map(mapper::map);
    }
}
