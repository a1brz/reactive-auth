package io.a1brz.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import reactor.core.publisher.Mono;

public interface TokenRepository {

    Mono<RefreshToken> save(RefreshToken token);

    Mono<RefreshToken> get(String token);

    Mono<RefreshToken> update(RefreshToken token);

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    class RefreshToken {
        private String token;
        private String userId;
        @Builder.Default
        private boolean isActive = Boolean.TRUE;
    }
}
