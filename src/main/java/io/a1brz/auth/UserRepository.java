package io.a1brz.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public interface UserRepository {

    Mono<User> save(User user);

    Mono<User> findByUserId(String userId);

    Mono<User> findByUsername(String username);

    Mono<Boolean> existsByUsername(String username);

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder
    class User implements UserDetails {
        @Builder.Default
        private String userId = UUID.randomUUID().toString();
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private String password;
        @Builder.Default
        private Boolean enabled = Boolean.FALSE;
        private List<Role> roles;
        @Builder.Default
        private LocalDateTime created = LocalDateTime.now(Clock.systemUTC());
        @Builder.Default
        private LocalDateTime updated = LocalDateTime.now(Clock.systemUTC());

        @Override
        public boolean isAccountNonExpired() {
            return false;
        }

        @Override
        public boolean isAccountNonLocked() {
            return false;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return false;
        }

        @Override
        public boolean isEnabled() {
            return this.enabled;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return this.roles.stream().map(role -> new SimpleGrantedAuthority(role.authority())).collect(Collectors.toList());
        }

        enum Role {
            USER, ADMIN;

            public String authority() {
                return "ROLE_" + this.name();
            }
        }
    }
}
