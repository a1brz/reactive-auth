package io.a1brz.auth;

import io.a1brz.auth.UserRepository.User.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Service
class AuthServiceImpl implements AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final TokenService tokenService;

    @Autowired
    AuthServiceImpl(PasswordEncoder passwordEncoder, UserRepository userRepository, TokenService tokenService) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.tokenService = tokenService;
    }

    @Override
    public Mono<Boolean> register(RegistrationRequest request) {
        return userRepository.existsByUsername(request.getUsername())
                .filter(exists -> !exists)
                .switchIfEmpty(Mono.error(new RuntimeException("User already exist")))
                .map(e -> UserRepository.User.builder()
                        .username(request.getUsername())
                        .password(passwordEncoder.encode(request.getPassword()))
                        .firstName(request.getFirstName())
                        .lastName(request.getLastName())
                        .email(request.getEmail())
                        .roles(Collections.singletonList(Role.USER))
                        .enabled(Boolean.TRUE)
                        .build())
                .flatMap(userRepository::save)
                .map(UserDetails::isEnabled);
    }

    @Override
    public Mono<AuthResponse> authenticate(AuthRequest authRequest) {
        return userRepository.findByUsername(authRequest.getUsername())
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                .filter(UserRepository.User::isEnabled)
                .switchIfEmpty(Mono.error(new RuntimeException("User not enabled")))
                .filter(user -> passwordEncoder.matches(authRequest.getPassword(), user.getPassword()))
                .switchIfEmpty(Mono.error(new RuntimeException("Wrong password")))
                .flatMap(user -> Mono.zip(
                        tokenService.generateAccessToken(user),
                        tokenService.generateRefreshToken(user.getUserId())))
                .map(tokens -> new AuthResponse(tokens.getT1(), tokens.getT2()));
    }

    @Override
    public Mono<String> refreshAccessToken(TokenRequest request) {
        return Mono.just(request)
                .map(TokenRequest::getRefreshToken)
                .filterWhen(tokenService::validateRefreshToken)
                .switchIfEmpty(Mono.error(new RuntimeException("Token is not valid")))
                .flatMap(tokenService::extractUserId)
                .flatMap(userRepository::findByUserId)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                .flatMap(tokenService::generateAccessToken);
    }

    @Override
    public Mono<Boolean> invalidateRefreshToken(TokenRequest request) {
        return Mono.just(request)
                .map(TokenRequest::getRefreshToken)
                .filterWhen(tokenService::validateRefreshToken)
                .switchIfEmpty(Mono.error(new RuntimeException("Token is not valid")))
                .flatMap(tokenService::deactivateRefreshToken);
    }
}