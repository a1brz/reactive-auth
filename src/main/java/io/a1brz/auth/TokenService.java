package io.a1brz.auth;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface TokenService {

    Mono<String> generateAccessToken(UserRepository.User user);

    Mono<String> generateRefreshToken(String userId);

    Mono<Boolean> validateAccessToken(String token);

    Mono<Boolean> validateRefreshToken(String token);

    Mono<String> extractUserId(String token);

    Flux<String> extractRoles(String token);

    Mono<Boolean> deactivateRefreshToken(String token);
}
