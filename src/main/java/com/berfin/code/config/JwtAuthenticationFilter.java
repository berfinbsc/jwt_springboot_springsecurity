package com.amigos.code.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String jwt;
        final String userEmail;
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
        }


        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserName(jwt);


//kullanıcının kimlik doğrulama (authentication) durumunu kontrol eder
//kullanıcı bır ıstekte bulunur ancak oturum acmamıstır jwt uzerınden username alınır user.detaıls cekılır ve kımlık dogrulaması yapılır

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //jwt tarih kontrolü-jwtdeki user ile userDetails.getUser aynı mo kontrolü
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // nesnesinin ayrıntılarını ayarlamak için kullanılır. Bu ayrıntılar, kimlik doğrulama bilgisini daha spesifik hale getirir ve güvenlik kontrolleri sırasında kullanılabilir.
                SecurityContextHolder.getContext().setAuthentication(authToken);
                //  Bu, kullanıcının oturum açtığını ve kimlik doğrulamasının başarılı olduğunu diğer parçalar için bildirir.            }
            }
        }


    }
}