package io.a1brz.auth;

import reactor.core.publisher.Mono;

public interface TokenRepository {

    Mono<RefreshToken> save(RefreshToken token);

    Mono<RefreshToken> get(String token);

    Mono<RefreshToken> update(RefreshToken token);

    class RefreshToken {
        private String token;
        private String userId;
        private boolean isActive;

        public RefreshToken(String token, String userId, boolean isActive) {
            this.token = token;
            this.userId = userId;
            this.isActive = isActive;
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public boolean isActive() {
            return isActive;
        }

        public void setActive(boolean active) {
            isActive = active;
        }
    }
}
