package com.group_A.TRIPNEST.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final String frontendRedirectUri;

    public OAuth2AuthenticationFailureHandler(@Value("${app.oauth2.frontend-redirect-uri:}") String frontendRedirectUri) {
        this.frontendRedirectUri = frontendRedirectUri;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationException exception) throws IOException {
        if (frontendRedirectUri != null && !frontendRedirectUri.isBlank()) {
            String targetUrl = UriComponentsBuilder.fromUriString(frontendRedirectUri)
                    .queryParam("error", exception.getMessage() == null ? "oauth2_login_failed" : exception.getMessage())
                    .build().toUriString();
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
            return;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        String message = exception.getMessage() == null ? "Google login failed" : exception.getMessage();
        response.getWriter().write("{\"success\":false,\"message\":\"" + message.replace("\"", "'") + "\"}");
    }
}
