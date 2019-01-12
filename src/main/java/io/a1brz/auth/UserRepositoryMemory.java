package io.a1brz.auth;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Repository
class UserRepositoryMemory implements UserRepository {
    private static final Map<String, User> USERS = new HashMap<>();

    @Override
    public Mono<User> save(User user) {
        return Mono.justOrEmpty(USERS.put(user.getUserId(), user))
                .thenReturn(user);
    }

    @Override
    public Mono<User> findByUserId(String userId) {
        return Mono.just(USERS.get(userId));
    }

    @Override
    public Mono<User> findByUsername(String username) {
        return Flux.fromIterable(USERS.values())
                .filter(user -> user.getUsername().equals(username))
                .last();
    }

    @Override
    public Mono<Boolean> existsByUsername(String username) {
        return Mono.just(USERS.values().stream().anyMatch(user -> user.getUsername().equals(username)));
    }
}
