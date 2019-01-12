package io.a1brz.auth;

import io.a1brz.auth.AuthService.AuthRequest;
import io.a1brz.auth.AuthService.RegistrationRequest;
import io.a1brz.auth.AuthService.TokenRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;

@RestController
public class AuthController {
    private final AuthService service;

    @Autowired
    AuthController(AuthService service) {
        this.service = service;
    }

    @RequestMapping(value = "register", method = RequestMethod.POST)
    public Mono<ResponseEntity<Object>> register(@RequestBody RegistrationRequest request) {
        return service.register(request)
                .then(Mono.just(ResponseEntity.created(URI.create("/authenticate")).build()));
    }

    @RequestMapping(value = "authenticate", method = RequestMethod.POST)
    public Mono<AuthService.AuthResponse> authenticate(@RequestBody AuthRequest request) {
        return service.authenticate(request);
    }

    @RequestMapping(value = "token/refresh", method = RequestMethod.POST)
    public Mono<String> refreshToken(@RequestBody TokenRequest request) {
        return service.refreshAccessToken(request);
    }

    @RequestMapping(value = "token/invalidate", method = RequestMethod.POST)
    public Mono<Boolean> logout(@RequestBody TokenRequest request) {
        return service.invalidateRefreshToken(request);
    }
}
