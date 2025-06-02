package vn.jason.springoauth2jwt.controller;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.jason.springoauth2jwt.security.JwtTokenProvider;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);



    @Autowired
    private JwtTokenProvider tokenProvider; // Inject if you need to read claims directly for /me

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal Object principal, HttpServletRequest request) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logger.info("Current user authentication: {}", authentication);
        logger.info("Current user principal: {}", principal);
        if (authentication == null || !authentication.isAuthenticated()) {
            logger.warn("No authenticated user found in the security context.");
            return ResponseEntity.status(401).body("Unauthorized");
        }
        if(principal instanceof String) {
            String bearerToken = request.getHeader("Authorization");
            String jwt = null;
            if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
                jwt = bearerToken.substring(7);
            }
            if (jwt != null && tokenProvider.validateToken(jwt)) { // tokenProvider vẫn cần thiết
                Claims claims = tokenProvider.getAllClaimsFromToken(jwt);
                Map<String, Object> userDetails = new HashMap<>();
                userDetails.put("subject", claims.getSubject()); // Chính là principal (username/email)
                userDetails.put("name", claims.get("name"));
                userDetails.put("email", claims.get("email"));
                userDetails.put("picture", claims.get("picture"));
                return ResponseEntity.ok(userDetails);
            }
            return ResponseEntity.ok(Map.of("username", principal));
        }
        return ResponseEntity.ok(Map.of("principal", principal != null ? principal.toString() : "N/A"));
    }


    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        logger.info("Processing logout request (dev mode - Bearer token)");
        SecurityContextHolder.clearContext(); // Xóa context bảo mật phía server cho request hiện tại
        return ResponseEntity.ok("Logout successful. Client should discard the JWT.");
    }
}