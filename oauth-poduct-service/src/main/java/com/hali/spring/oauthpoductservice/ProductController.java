package com.hali.spring.oauthpoductservice;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@Slf4j
public class ProductController {
    @GetMapping("/")
    Mono<ProductDto> getMapping(@AuthenticationPrincipal JwtAuthenticationToken token){
        log.info("hi " + token.getName() );
        return Mono.just(new ProductDto("1","name"));
    }
}
