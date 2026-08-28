package com.group_A.TRIPNEST.security.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.group_A.TRIPNEST.dto.AuthResponse;
import com.group_A.TRIPNEST.entity.User;
import com.group_A.TRIPNEST.repository.UserRepository;
import com.group_A.TRIPNEST.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Runs once Spring Security has completed the Google OAuth2 handshake and
 * {@link CustomOAuth2UserService} has resolved a local {@link User}.
 * Issues our own JWT so the client ends up with exactly the same kind of token
 * it would get from POST /api/auth/login.
 */
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository users;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;
    private final String frontendRedirectUri;

    public OAuth2AuthenticationSuccessHandler(UserRepository users,
                                               JwtService jwtService,
                                               ObjectMapper objectMapper,
                                               @Value("${app.oauth2.frontend-redirect-uri:}") String frontendRedirectUri) {
        this.users = users;
        this.jwtService = jwtService;
        this.objectMapper = objectMapper;
        this.frontendRedirectUri = frontendRedirectUri;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws IOException {
        if (response.isCommitted()) {
            return;
        }

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        User user = users.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("Authenticated Google user was not persisted: " + email));

        String token = jwtService.generateToken(user);
        AuthResponse authResponse = new AuthResponse(true, "Google login successful", user.getEmail(),
                token, "Bearer", jwtService.getExpirationMs() / 1000);

        clearAuthenticationAttributes(request);

        if (frontendRedirectUri != null && !frontendRedirectUri.isBlank()) {
            String targetUrl = UriComponentsBuilder.fromUriString(frontendRedirectUri)
                    .queryParam("token", token)
                    .queryParam("email", user.getEmail())
                    .build().toUriString();
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(authResponse));
    }
}
