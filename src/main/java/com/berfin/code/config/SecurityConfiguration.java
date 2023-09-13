package com.spring.proje.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static com.spring.proje.entities.Role.ADMIN;
import static com.spring.proje.entities.Role.USER;
import static com.spring.proje.entities.Permission.ADMIN_READ;
import static com.spring.proje.entities.Permission.USER_READ;
import static com.spring.proje.entities.Permission.ADMIN_CREATE;
import static com.spring.proje.entities.Permission.USER_CREATE;
import static com.spring.proje.entities.Permission.ADMIN_UPDATE;
import static com.spring.proje.entities.Permission.USER_UPDATE;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    //login sayfası icin jwt ye gerek yok diger islemler icin gerekli
@Autowired
    private final JwtAuthenticationFilter jwtAuthFilter;
@Autowired
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
       http.cors().and().csrf().disable()
       .authorizeRequests()
       .requestMatchers("/api/v1/auth/**")
       .permitAll()
        .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), USER.name())
         .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), USER_READ.name())
        .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), USER_CREATE.name())
        .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), USER_UPDATE.name())
               .anyRequest()
               .authenticated()
               .and()
               .authenticationProvider(authenticationProvider)
               .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();

    }




/*

        //noinspection removal
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

*/






















}
