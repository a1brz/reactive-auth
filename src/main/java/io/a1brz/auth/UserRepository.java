package io.a1brz.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public interface UserRepository {

    Mono<User> save(User user);

    Mono<User> findByUserId(String userId);

    Mono<User> findByUsername(String username);

    Mono<Boolean> existsByUsername(String username);

    class User implements UserDetails {
        private String userId;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private String password;
        private Boolean enabled;
        private List<Role> roles;
        private LocalDateTime created;
        private LocalDateTime updated;

        public User() {
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        @Override
        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getFirstName() {
            return firstName;
        }

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        }

        public String getLastName() {
            return lastName;
        }

        public void setLastName(String lastName) {
            this.lastName = lastName;
        }

        @Override
        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public Boolean getEnabled() {
            return enabled;
        }

        public void setEnabled(Boolean enabled) {
            this.enabled = enabled;
        }

        public List<Role> getRoles() {
            return roles;
        }

        public void setRoles(List<Role> roles) {
            this.roles = roles;
        }

        public LocalDateTime getCreated() {
            return created;
        }

        public void setCreated(LocalDateTime created) {
            this.created = created;
        }

        public LocalDateTime getUpdated() {
            return updated;
        }

        public void setUpdated(LocalDateTime updated) {
            this.updated = updated;
        }

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
