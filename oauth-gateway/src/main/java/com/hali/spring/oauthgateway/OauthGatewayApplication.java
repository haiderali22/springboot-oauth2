package com.hali.spring.oauthgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class OauthGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(OauthGatewayApplication.class, args);
    }

}
