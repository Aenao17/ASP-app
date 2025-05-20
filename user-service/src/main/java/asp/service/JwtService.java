package asp.service;

import asp.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    public String extractIdFromAuthorization(String authorization) {
        return extractUsername(authorization.split(" ")[1]);
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); // subject = userId
    }

    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(User user, Long jti) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", user.getRole().name()); // 🟢 rolul e acum în token

        return generateToken(extraClaims, user, jti);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            User user,
            Long jti
    ) {
        return buildToken(extraClaims, user, jti, jwtExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            User user,
            Long jti,
            long expiration
    ) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setId(jti.toString())
                .setSubject(user.getId().toString())
                .setIssuer("spark")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token) {
        return !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}