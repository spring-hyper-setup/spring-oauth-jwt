package vn.jason.springoauth2jwt.security;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    private final JwtTokenProvider tokenProvider;


    @Value("${server.servlet.session.cookie.secure}")
    private boolean useSecureCookie;

    @Autowired
    public OAuth2AuthenticationSuccessHandler(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;

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
            logger.info("Generated JWT for dev: {}", jwt);

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("message", "OAuth2 authentication successful. JWT provided below.");
            responseBody.put("accessToken", jwt);
            Map<String,Object> userAttributes = oauth2User.getAttributes();
            responseBody.put("userAttributes", userAttributes);
            ObjectMapper objectMapper = new ObjectMapper();
            response.getWriter().write(objectMapper.writeValueAsString(responseBody));
            response.setStatus(HttpServletResponse.SC_OK);

        } else {
            logger.warn("OAuth2 Principal is not an instance of OAuth2User: {}", authentication.getPrincipal().getClass().getName());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("{\"error\":\"Authentication failed: Principal is not OAuth2User\"}");
        }
    }
}
