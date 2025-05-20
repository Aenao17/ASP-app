package asp.service;

import asp.auth.AuthenticationRequest;
import asp.auth.AuthenticationResponse;
import asp.auth.RegisterRequest;
import asp.model.Role;
import asp.model.Token;
import asp.model.TokenType;
import asp.model.User;
import asp.repository.TokenRepository;
import asp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow();
        revokeAllUserTokens(user);
        Token t = saveUserToken(user);
        var jwtToken = jwtService.generateToken(user, t.getId());
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    private final PasswordEncoder passwordEncoder;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .institutionalEmail(request.getInstitutionalEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .build();

        var savedUser = userRepository.save(user);
        var token = saveUserToken(savedUser);
        var jwt = jwtService.generateToken(savedUser, token.getId());

        return AuthenticationResponse.builder()
                .token(jwt)
                .build();
    }


    private Token saveUserToken(User user) {
        var token = Token.builder()
                .user(user)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        return tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}