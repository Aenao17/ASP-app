package asp.controller;

import asp.auth.AuthenticationRequest;
import asp.auth.AuthenticationResponse;
import asp.auth.RegisterRequest;
import asp.service.AuthenticationService;
import asp.service.LogoutService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Autentificare")
public class AuthenticationController {

    private final AuthenticationService authService;
    private final LogoutService logoutService;

    @Operation(summary = "Înregistrare utilizator nou")
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @Operation(summary = "Autentificare utilizator (login)")
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @Operation(summary = "Logout utilizator")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {
        logoutService.logout(request, response, authentication);
        return ResponseEntity.ok().build();
    }
}
