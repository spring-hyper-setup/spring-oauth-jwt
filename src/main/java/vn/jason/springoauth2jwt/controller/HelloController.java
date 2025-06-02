package vn.jason.springoauth2jwt.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class HelloController {

    @GetMapping("/hello")
    public Map<String, String> sayHello(@AuthenticationPrincipal String username) {
        // username will be the email extracted from JWT
        return Map.of("message", "Hello, " + username + "! This is a protected resource.");
    }

    @GetMapping("/public/info")
    public Map<String, String> publicInfo() {
        return Map.of("message", "This is public information, anyone can access it!");
    }
}
