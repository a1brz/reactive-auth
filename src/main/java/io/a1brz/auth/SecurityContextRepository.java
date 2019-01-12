package io.a1brz.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
class SecurityContextRepository implements ServerSecurityContextRepository {
    private static final String TOKEN_PREFIX = "Bearer ";
    private final AuthManager authManager;

    @Autowired
    SecurityContextRepository(AuthManager authManager) {
        this.authManager = authManager;
    }

    @Override
    public Mono<Void> save(ServerWebExchange swe, SecurityContext sc) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange swe) {
        return Mono.just(swe.getRequest())
                .map(request -> request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(token -> token != null && token.startsWith(TOKEN_PREFIX))
                .map(token -> token.substring(TOKEN_PREFIX.length()))
                .map(token -> new UsernamePasswordAuthenticationToken(token, token))
                .flatMap(authManager::authenticate)
                .map(SecurityContextImpl::new);
    }
}