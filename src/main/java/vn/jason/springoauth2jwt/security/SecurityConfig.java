package vn.jason.springoauth2jwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter; // Autowire the filter

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        // By default, Spring Security's CsrfFilter will use this to load the token if the attribute name is not set.
        // For SPAs, it's common to rely on the X-XSRF-TOKEN header read from the cookie.
        // requestHandler.setCsrfRequestAttributeName(null); // Setting to null ensures it's not read from request attribute if you only want header based.

        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // Makes XSRF-TOKEN cookie readable by JS
                        .csrfTokenRequestHandler(requestHandler) // For Spring Security 6+
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(
                                "/", "/error", "/favicon.ico",
                                "/login-success.html", // Allow access to success page
                                "/**/*.png", "/**/*.gif", "/**/*.svg", "/**/*.jpg",
                                "/**/*.html", "/**/*.css", "/**/*.js"
                        ).permitAll()
                        .requestMatchers("/oauth2/**", "/login/oauth2/code/**").permitAll() // OAuth2 login flow
                        .requestMatchers("/api/auth/logout").permitAll() // Logout endpoint
                        .requestMatchers("/api/public/**").permitAll() // Any public APIs
                        .requestMatchers("/api/user/me").authenticated() // /me endpoint requires authentication
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                                // No need to specify loginPage if using the default /oauth2/authorization/{registrationId}
                                .successHandler(oAuth2AuthenticationSuccessHandler)
                        // You can also add .failureHandler(...)
                );

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}