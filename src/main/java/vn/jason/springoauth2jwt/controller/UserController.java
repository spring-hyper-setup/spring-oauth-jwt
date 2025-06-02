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
@RequestMapping("/api")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Value("${jwt.cookie-name}")
    private String jwtCookieName;

    @Value("${server.servlet.session.cookie.secure}")
    private boolean useSecureCookie;

    @Autowired
    private JwtTokenProvider tokenProvider; // Inject if you need to read claims directly for /me

    @GetMapping("/user/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal Object principal, HttpServletRequest request) {
        // @AuthenticationPrincipal will inject the principal set by JwtAuthenticationFilter (which is username/email)
        // Or you can get it from SecurityContextHolder
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        // For simple principal (String - email)
        if (principal instanceof String) {
            // If you need more details than just the email, and those details are in the JWT claims:
            String jwt = null;
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (jwtCookieName.equals(cookie.getName())) {
                        jwt = cookie.getValue();
                        break;
                    }
                }
            }

            if (jwt != null && tokenProvider.validateToken(jwt)) {
                Claims claims = tokenProvider.getAllClaimsFromToken(jwt);
                Map<String, Object> userDetails = new HashMap<>();
                userDetails.put("subject", claims.getSubject());
                userDetails.put("name", claims.get("name"));
                userDetails.put("email", claims.get("email"));
                userDetails.put("picture", claims.get("picture"));
                // Add any other claims you put in the token
                return ResponseEntity.ok(userDetails);
            }
            // Fallback if claims cannot be read but principal is there
            return ResponseEntity.ok(Map.of("username", principal));
        }

        // If OAuth2User is somehow still the principal (less likely after JWT filter)
        if (principal instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) principal;
            return ResponseEntity.ok(oauth2User.getAttributes());
        }

        return ResponseEntity.ok(Map.of("principal", principal != null ? principal.toString() : "N/A"));
    }


    @PostMapping("/auth/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        logger.info("Processing logout request");
        Cookie cookie = new Cookie(jwtCookieName, null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(useSecureCookie);
        cookie.setMaxAge(0); // Expire the cookie immediately

        response.addCookie(cookie);
        logger.info("JWT cookie '{}' cleared for logout.", jwtCookieName);
        return ResponseEntity.ok("Logout successful. Please clear any local state if you are a frontend client.");
    }
}