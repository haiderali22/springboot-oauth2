package com.hali.spring.oauthpoductservice;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) {

        http
                .oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec.jwt(jwtSpec -> jwtSpec
                        .jwtDecoder( new JWTDecoder())
//                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                ))
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
                        .anyExchange().authenticated()
                );

        return http.build();
    }

//    @Bean
//    public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
//        var jwtGrantedAuthoritiesConverter = new ReactiveJwtAuthenticationConverter();
//        jwtGrantedAuthoritiesConverter.setJwtGrantedAuthoritiesConverter();
//        jwtGrantedAuthoritiesConverter.setPrincipalClaimName("roles");
//
//        var jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
//        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
//                new ReactiveJwtGrantedAuthoritiesConverterAdapter(jwtGrantedAuthoritiesConverter));
//
//        return jwtAuthenticationConverter;
//    }
}