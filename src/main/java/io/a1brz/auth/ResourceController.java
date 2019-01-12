package io.a1brz.auth;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
public class ResourceController {
    @RequestMapping(value = "resource/user", method = RequestMethod.GET)
    @PreAuthorize("hasRole('USER')")
    public Mono<ResponseEntity<String>> user() {
        return Mono.just(ResponseEntity.ok("Content for user"));
    }

    @RequestMapping(value = "resource/admin", method = RequestMethod.GET)
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<ResponseEntity<String>> admin() {
        return Mono.just(ResponseEntity.ok("Content for admin"));
    }

    @RequestMapping(value = "resource/user-or-admin", method = RequestMethod.GET)
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public Mono<ResponseEntity<String>> userOrAdmin() {
        return Mono.just(ResponseEntity.ok("Content for user or admin"));
    }

    @GetMapping(value = "resource/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @PreAuthorize("hasRole('USER')")
    public Flux<Integer> streamData() {
        return Flux.just(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    }
}