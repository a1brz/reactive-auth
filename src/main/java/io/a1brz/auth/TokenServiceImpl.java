package io.a1brz.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Payload;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Date;

@Service
public class TokenServiceImpl implements TokenService {
    private final static String ROLES_CLAIM = "roles";
    private final Long accessTokenExpirationInSeconds;
    private final Long refreshTokenExpirationInSeconds;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final TokenRepository tokenRepository;

    @Autowired
    TokenServiceImpl(@Value("${jwt.secret}") String secret,
                     @Value("${jwt.accessTokenExpirationInSeconds}") Long accessTokenExpirationInSeconds,
                     @Value("${jwt.refreshTokenExpirationInSeconds}") Long refreshTokenExpirationInSeconds,
                     TokenRepository tokenRepository) {
        this.accessTokenExpirationInSeconds = accessTokenExpirationInSeconds;
        this.refreshTokenExpirationInSeconds = refreshTokenExpirationInSeconds;
        this.tokenRepository = tokenRepository;

        algorithm = Algorithm.HMAC512(secret);
        verifier = JWT.require(algorithm).build();
    }

    @Override
    public Mono<String> generateAccessToken(UserRepository.User user) {
        return Mono.just(Instant.now())
                .map(creationDate -> JWT.create()
                        .withSubject(user.getUserId())
                        .withIssuedAt(Date.from(creationDate))
                        .withExpiresAt(Date.from(creationDate.plusSeconds(accessTokenExpirationInSeconds)))
                        .withArrayClaim(ROLES_CLAIM, user.getRoles().stream().map(Enum::name).toArray(String[]::new))
                        .sign(algorithm));
    }

    @Override
    public Mono<String> generateRefreshToken(String userId) {
        return Mono.just(Instant.now())
                .map(creationDate -> JWT.create()
                        .withSubject(userId)
                        .withIssuedAt(Date.from(creationDate))
                        .withExpiresAt(Date.from(creationDate.plusSeconds(refreshTokenExpirationInSeconds)))
                        .sign(algorithm))
                .map(token -> TokenRepository.RefreshToken.builder()
                        .userId(userId)
                        .token(token)
                        .build())
                .flatMap(tokenRepository::save)
                .map(TokenRepository.RefreshToken::getToken);
    }

    @Override
    public Mono<Boolean> validateAccessToken(String token) {
        return Mono.just(token)
                .map(this::decodeToken)
                .map(Payload::getExpiresAt)
                .map(expirationDate -> expirationDate.after(Date.from(Instant.now())));
    }

    @Override
    public Mono<Boolean> validateRefreshToken(String token) {
        return Mono.just(token)
                .flatMap(tokenRepository::get)
                .map(TokenRepository.RefreshToken::isActive);
    }

    @Override
    public Mono<String> extractUserId(String token) {
        return Mono.just(token)
                .map(this::decodeToken)
                .map(Payload::getSubject);
    }

    @Override
    public Flux<String> extractRoles(String token) {
        return Mono.just(token)
                .map(this::decodeToken)
                .map(decodedJWT -> decodedJWT.getClaim(ROLES_CLAIM))
                .filter(claim -> !claim.isNull())
                .flatMapIterable(claim -> claim.asList(String.class));
    }

    @Override
    public Mono<Boolean> deactivateRefreshToken(String token) {
        return tokenRepository.get(token)
                .doOnNext(refreshToken -> refreshToken.setActive(false))
                .flatMap(tokenRepository::update)
                .map(refreshToken -> !refreshToken.isActive());
    }

    private DecodedJWT decodeToken(String token) {
        return verifier.verify(token);
    }
}
