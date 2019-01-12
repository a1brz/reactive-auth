package io.a1brz.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
class AuthManager implements ReactiveAuthenticationManager {
    private final TokenService tokenService;

    @Autowired
    AuthManager(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.justOrEmpty(authentication.getCredentials().toString())
                .filterWhen(tokenService::validateAccessToken)
                .flatMap(accessToken -> tokenService.extractUserId(accessToken)
                        .flatMap(userId -> tokenService.extractRoles(accessToken)
                                .map(UserRepository.User.Role::valueOf)
                                .map(UserRepository.User.Role::authority)
                                .map(SimpleGrantedAuthority::new)
                                .collectList()
                                .map(authorities -> new UsernamePasswordAuthenticationToken(userId, null, authorities))));
    }
}