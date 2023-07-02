package com.hali.spring.oauthpoductservice;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@Slf4j
public class ProductController {
    @GetMapping("/")
    Mono<ProductDto> getMapping(){
        log.info("hi");
        return Mono.just(new ProductDto("1","name"));
    }
}
