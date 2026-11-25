package com.OffBeatGateway.config;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http) {

        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)

            .authorizeExchange(exchanges -> exchanges

                //PERMISO GENERAL PARA REACT

                .pathMatchers(HttpMethod.OPTIONS).permitAll()

                //PERMISOS DE PRODUCTOS

                .pathMatchers(HttpMethod.GET, "/api/v1/productos/**")
                    .permitAll()

                .pathMatchers(HttpMethod.POST,
                    "/api/v1/productos/lista",
                    "/api/v1/productos/descontar-stock")
                    .hasAnyRole("admin", "vendedor", "cliente")

                .pathMatchers("/api/v1/productos/**")
                    .hasRole("admin")

                //PERMISOS DE CATEGORÍAS

                .pathMatchers(HttpMethod.GET, "/api/v1/categorias/**")
                    .permitAll()

                .pathMatchers("/api/v1/categorias/**")
                    .hasRole("admin")

                //PERMISOS DE BLOGS

                .pathMatchers(HttpMethod.GET, "/api/v1/blogs/**")
                    .permitAll()

                .pathMatchers("/api/v1/blogs/**")
                    .hasRole("admin")

                //PERMISOS DE USUARIOS

                .pathMatchers(HttpMethod.POST,
                    "/api/v1/usuarios/login",
                    "/api/v1/usuarios/login/google",
                    "/api/v1/usuarios")
                    .permitAll()

                .pathMatchers(HttpMethod.GET, "/api/v1/usuarios/count")
                    .hasAnyRole("admin", "vendedor")

                .pathMatchers("/api/v1/usuarios/**")
                    .hasRole("admin")

                //PERMISOS DE COMENTARIOS

                .pathMatchers(HttpMethod.POST, "/api/v1/comentarios")
                    .permitAll()

                .pathMatchers("/api/v1/comentarios/**")
                    .hasRole("admin")

                //PERMISOS DE COMPRAS

                .pathMatchers(HttpMethod.POST, "/api/v1/compras")
                    .hasAnyRole("admin", "vendedor", "cliente")

                .pathMatchers(HttpMethod.GET, "/api/v1/compras/{id}")
                    .hasAnyRole("admin", "vendedor", "cliente")

                .pathMatchers("/api/v1/compras/**")
                    .hasRole("admin")

                .anyExchange().authenticated()
            )

            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt ->
                    jwt.jwtAuthenticationConverter(
                        new ReactiveJwtAuthenticationConverterAdapter(
                            jwtAuthenticationConverter()
                        )
                    )
                )
            )

            .build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {

        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);

        SecretKey secretKey = new SecretKeySpec(
            keyBytes,
            "HmacSHA256"
        );

        NimbusReactiveJwtDecoder decoder =
            NimbusReactiveJwtDecoder
                .withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        decoder.setJwtValidator(
            JwtValidators.createDefault()
        );

        return decoder;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {

        JwtGrantedAuthoritiesConverter authoritiesConverter =
            new JwtGrantedAuthoritiesConverter();

        authoritiesConverter.setAuthoritiesClaimName("rol");
        authoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter =
            new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(
            authoritiesConverter
        );

        return converter;
    }
}