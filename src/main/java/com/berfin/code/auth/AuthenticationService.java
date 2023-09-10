package com.amigos.code.auth;


import com.amigos.code.config.JwtService;
import com.amigos.code.user.Role;
import com.amigos.code.user.User;
import com.amigos.code.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
private final PasswordEncoder passwordEncoder;
private final UserRepository userRepository;
private final JwtService jwtService;
private final AuthenticationManager authenticationManager;
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
        request.getEmail(),request.getPassword()
));
var user=userRepository.findByEmail(request.getEmail())
        .orElseThrow();
var jwtToken=jwtService.generateToken(user);
return AuthenticationResponse
        .builder()
        .token(jwtToken)
        .build();

    }

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User
                .builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        var jwtToken=jwtService.generateToken(user);
        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
    }
}
