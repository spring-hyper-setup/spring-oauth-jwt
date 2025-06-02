package vn.jason.springoauth2jwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile; // Thêm để có thể cấu hình riêng cho dev
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// Bỏ import CSRF nếu không dùng nữa trong dev
// import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
// import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    // @Profile("dev") // Bạn có thể tạo một SecurityConfig riêng cho dev profile và disable CSRF ở đó
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler(); // Bỏ nếu disable CSRF

        http
                // VÔ HIỆU HÓA CSRF ĐỂ TEST DEV DỄ DÀNG HƠN
                // LƯU Ý: TUYỆT ĐỐI KHÔNG LÀM ĐIỀU NÀY Ở PRODUCTION
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        // Các requestMatchers giữ nguyên hoặc điều chỉnh lại đường dẫn logout nếu cần
                                .requestMatchers("/", "/error", "/favicon.ico", "/login-success.html").permitAll()
                        .requestMatchers("/oauth2/**").permitAll()
                        .requestMatchers("/login/oauth2/code").permitAll()
                        .requestMatchers("/api/auth/logout").permitAll() // Đảm bảo khớp với UserController
                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/api/user/me").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                );

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Bạn có thể tạo một Bean SecurityFilterChain khác cho production với CSRF được bật
    /*
    @Bean
    @Profile("!dev") // Kích hoạt khi không phải dev profile
    public SecurityFilterChain productionFilterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(requestHandler)
            )
            // ... các cấu hình khác tương tự nhưng BẬT CSRF
            .authorizeHttpRequests(authz -> authz
                // ... (như trên)
            )
            // ...
        return http.build();
    }
    */
}