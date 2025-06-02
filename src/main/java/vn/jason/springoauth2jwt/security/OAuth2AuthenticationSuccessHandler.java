package vn.jason.springoauth2jwt.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    private final JwtTokenProvider tokenProvider;
    private final String frontendRedirectUri;
    private final String jwtCookieName;
    private final long jwtExpirationMs;

    @Value("${server.servlet.session.cookie.secure}")
    private boolean useSecureCookie;

    @Autowired
    public OAuth2AuthenticationSuccessHandler(JwtTokenProvider tokenProvider,
                                              @Value("${app.redirect-uri}") String frontendRedirectUri,
                                              @Value("${jwt.cookie-name}") String jwtCookieName,
                                              @Value("${jwt.expiration}") long jwtExpirationMs) {
        this.tokenProvider = tokenProvider;
        this.frontendRedirectUri = frontendRedirectUri;
        this.jwtCookieName = jwtCookieName;
        this.jwtExpirationMs = jwtExpirationMs;
        setDefaultTargetUrl(frontendRedirectUri); // Set default target URL for redirection
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException, IOException {
        logger.info("OAuth2 Authentication Successful. Principal: {}", authentication.getPrincipal());
        if (authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

            // TODO: Implement logic to find or create user in your database based on oauth2User attributes
            // String email = oauth2User.getAttribute("email");
            // User user = userService.processOAuth2User(email, oauth2User.getAttribute("name"), oauth2User.getAttribute("picture"));
            // Then, you might want to include your internal user ID or roles in the JWT.

            String jwt = tokenProvider.generateToken(oauth2User);

            Cookie jwtCookie = new Cookie(jwtCookieName, jwt);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(useSecureCookie); // Set based on profile/environment
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge((int) TimeUnit.MILLISECONDS.toSeconds(jwtExpirationMs));
            // jwtCookie.setSameSite("Lax"); // Consider explicit SameSite, though Spring Boot 3+ defaults to Lax

            response.addCookie(jwtCookie);
            logger.info("JWT cookie '{}' set. Redirecting to: {}", jwtCookieName, frontendRedirectUri);

            // Instead of returning JSON, we redirect as per SimpleUrlAuthenticationSuccessHandler
            getRedirectStrategy().sendRedirect(request, response, determineTargetUrl(request, response, authentication));

        } else {
            logger.warn("OAuth2 Principal is not an instance of OAuth2User: {}", authentication.getPrincipal().getClass());
            super.onAuthenticationSuccess(request, response, authentication); // Fallback to default behavior
        }
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // You can add logic here to customize the target URL based on roles or other attributes if needed
        return frontendRedirectUri;
    }
}
