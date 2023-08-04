package com.hali.spring.oauthgateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;


@Configuration
public class CorsConfig  {
    @Bean
    public CorsWebFilter corsWebFilter() {

        final UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config=new CorsConfiguration();
        config.addAllowedHeader(CorsConfiguration.ALL);
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"));
        config.addAllowedOrigin("http://127.0.0.1:3000");


        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }


}