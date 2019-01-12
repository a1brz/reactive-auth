package io.a1brz.auth;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Repository
public class TokenRepositoryMemory implements TokenRepository {
    private static final Map<String, RefreshToken> TOKENS = new HashMap<>();

    @Override
    public Mono<RefreshToken> save(RefreshToken token) {
        return Mono.justOrEmpty(TOKENS.put(token.getToken(), token))
                .thenReturn(token);
    }

    @Override
    public Mono<RefreshToken> get(String token) {
        return Mono.justOrEmpty(TOKENS.get(token));
    }

    @Override
    public Mono<RefreshToken> update(RefreshToken token) {
        return Mono.justOrEmpty(TOKENS.replace(token.getToken(), token));
    }
}
