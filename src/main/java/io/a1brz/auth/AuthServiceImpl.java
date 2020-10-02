package io.a1brz.auth;

import io.a1brz.auth.UserRepository.User;
import io.a1brz.auth.UserRepository.User.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;

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
                .map(e -> {
                    User user = new User();
                    user.setUserId(UUID.randomUUID().toString());
                    user.setUsername(request.getUsername());
                    user.setPassword(passwordEncoder.encode(request.getPassword()));
                    user.setFirstName(request.getFirstName());
                    user.setLastName(request.getFirstName());
                    user.setEmail(request.getEmail());
                    user.setRoles(Collections.singletonList(Role.USER));
                    user.setEnabled(Boolean.TRUE);
                    user.setCreated(LocalDateTime.now(Clock.systemUTC()));
                    user.setUpdated(LocalDateTime.now(Clock.systemUTC()));

                    return user;
                })
                .flatMap(userRepository::save)
                .map(UserDetails::isEnabled);
    }

    @Override
    public Mono<AuthResponse> authenticate(AuthRequest authRequest) {
        return userRepository.findByUsername(authRequest.getUsername())
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                .filter(User::isEnabled)
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