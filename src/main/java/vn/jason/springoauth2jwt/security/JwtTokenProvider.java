package vn.jason.springoauth2jwt.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.expiration}")
    private long jwtExpiration;

    private SecretKey jwtSecretKey;

    @PostConstruct
    public void init() {
        this.jwtSecretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        logger.info( "Secret key line 26"+ jwtSecretKey.toString());
    }

    public String generateToken(OAuth2User oauth2User){
        Map<String,Object> attributes = oauth2User.getAttributes();
        attributes.forEach( (k,v)->{
            logger.info("Attribute: {} = {}", k, v);
        });

        String subject = (String) attributes.get("email");
        if(subject == null){
            subject = (String) attributes.get("sub");
        }
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);
        String jwt= Jwts.builder()
                .setSubject(subject)
                .claim("name", attributes.get("name"))
                .claim("email", attributes.get("email"))
                .claim("picture", attributes.get("picture"))
                // You can add more custom claims if needed
                // e.g., internal user ID after mapping/creating user in your DB
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(jwtSecretKey, SignatureAlgorithm.HS256)
                .compact();

        logger.info("Generated JWT: {}", jwt);
        return jwt;
    }
    public String getUsernameFromJWT(String token) { // Changed from getUserIdFromJWT to reflect email/subject
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(jwtSecretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(jwtSecretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(jwtSecretKey).build().parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        } catch (io.jsonwebtoken.security.SignatureException e) {
            logger.error("JWT signature does not match locally computed signature: {}", e.getMessage());
        }
        return false;
    }
}
