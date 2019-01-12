package io.a1brz.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import reactor.core.publisher.Mono;

public interface AuthService {

    Mono<Boolean> register(RegistrationRequest request);

    Mono<AuthResponse> authenticate(AuthRequest request);

    Mono<String> refreshAccessToken(TokenRequest request);

    Mono<Boolean> invalidateRefreshToken(TokenRequest request);

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    class AuthRequest {
        private String username;
        private String password;
    }

    @Data
    @AllArgsConstructor
    class AuthResponse {
        private String accessToken;
        private String refreshToken;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    class RegistrationRequest {
        private String username;
        private String password;
        private String email;
        private String firstName;
        private String lastName;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    class TokenRequest {
        private String refreshToken;
    }
}
