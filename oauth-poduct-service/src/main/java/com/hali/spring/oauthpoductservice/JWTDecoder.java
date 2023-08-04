package com.hali.spring.oauthpoductservice;

import com.nimbusds.jwt.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@Slf4j
public class JWTDecoder implements ReactiveJwtDecoder {
    @Override
    public Mono<Jwt> decode(String token) throws JwtException {

        try {
            if (StringUtils.hasText(token)) {

                SignedJWT signedJWT = SignedJWT.parse(token);
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

                Jwt.Builder jwtBuilder = Jwt.withTokenValue(token)
                        .header("alg", "none")
                        .subject(claimsSet.getSubject())
                        .claim(JwtClaimNames.ISS, "");


                Map<String, Object> claims = claimsSet.getClaims();


                if (!CollectionUtils.isEmpty(claims) && !CollectionUtils.isEmpty((Collection<String>) claims.get("roles"))) {
                    jwtBuilder.claim("scope", claims.get("roles"));
                }


//                // Convert the claims from Nimbus JWT to Spring JWT
//                Jwt.Builder jwtBuilder = Jwt.withTokenValue(token)
//                        .header("alg", "none") // Since it's unsecured, set alg as "none"
//                        .claim(JwtClaimNames.ISS, claimsSet.getIssuer())
//                        .claim(JwtClaimNames.SUB, claimsSet.getSubject())
//                        .claim(JwtClaimNames.AUD, claimsSet.getAudience())
//                        .claim(JwtClaimNames.EXP, claimsSet.getExpirationTime())
//                        .claim(JwtClaimNames.IAT, claimsSet.getIssueTime());
//

                return Mono.just(jwtBuilder.build());
            }

            return Mono.empty();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new JwtException("Error decoding token", e);
        }
    }
}