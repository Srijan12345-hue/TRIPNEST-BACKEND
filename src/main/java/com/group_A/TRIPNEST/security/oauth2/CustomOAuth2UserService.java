package com.group_A.TRIPNEST.security.oauth2;

import com.group_A.TRIPNEST.entity.Role;
import com.group_A.TRIPNEST.entity.User;
import com.group_A.TRIPNEST.entity.enums.AuthProvider;
import com.group_A.TRIPNEST.repository.RoleRepository;
import com.group_A.TRIPNEST.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.stream.Collectors;


@Service
public class CustomOAuth2UserService extends OidcUserService {

    private final UserRepository users;
    private final RoleRepository roles;
    private final org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
    private final String defaultRoleName;

    public CustomOAuth2UserService(UserRepository users,
                                    RoleRepository roles,
                                    org.springframework.security.crypto.password.PasswordEncoder passwordEncoder,
                                    @Value("${app.oauth2.default-role:USER}") String defaultRoleName) {
        this.users = users;
        this.roles = roles;
        this.passwordEncoder = passwordEncoder;
        this.defaultRoleName = defaultRoleName;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        String email = oidcUser.getEmail();
        Boolean emailVerified = oidcUser.getEmailVerified();
        if (email == null || email.isBlank()) {
            throw new OAuth2AuthenticationException(new OAuth2Error("email_not_found"),
                    "Google account did not return an email address.");
        }
        if (emailVerified != null && !emailVerified) {
            throw new OAuth2AuthenticationException(new OAuth2Error("email_not_verified"),
                    "Google email address is not verified.");
        }

        User user = provisionOrUpdateUser(oidcUser, email.trim().toLowerCase());

        return new DefaultOidcUser(
                user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                        .collect(Collectors.toSet()),
                oidcUser.getIdToken(),
                oidcUser.getUserInfo(),
                "email");
    }

    private User provisionOrUpdateUser(OidcUser oidcUser, String email) {
        String googleSub = oidcUser.getSubject();
        String firstName = oidcUser.getGivenName();
        String lastName = oidcUser.getFamilyName();
        String picture = oidcUser.getPicture();

        return users.findByEmail(email)
                .map(existing -> {
                    // Account already exists (e.g. was created via /api/auth/register with the same
                    // email, which Google has now verified as belonging to this person). Link it to
                    // Google rather than creating a duplicate, and keep the avatar in sync.
                    boolean changed = false;
                    if (existing.getProviderId() == null && googleSub != null) {
                        existing.setProviderId(googleSub);
                        changed = true;
                    }
                    if (existing.getAuthProvider() == AuthProvider.LOCAL) {
                        existing.setAuthProvider(AuthProvider.GOOGLE);
                        changed = true;
                    }
                    if (picture != null && !picture.equals(existing.getProfileImageUrl())) {
                        existing.setProfileImageUrl(picture);
                        changed = true;
                    }
                    return changed ? users.save(existing) : existing;
                })
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setFirstName(firstName != null ? firstName : "Google");
                    newUser.setLastName(lastName != null ? lastName : "User");
                    newUser.setProfileImageUrl(picture);
                    newUser.setAuthProvider(AuthProvider.GOOGLE);
                    newUser.setProviderId(googleSub);
                    // No local password: fill with a random, never-disclosed bcrypt hash so that
                    // /api/auth/login simply fails with bad credentials for this account instead of NPE-ing.
                    newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
                    newUser.getRoles().add(defaultRole());
                    return users.save(newUser);
                });
    }

    private Role defaultRole() {
        return roles.findByName(defaultRoleName)
                .orElseGet(() -> roles.save(new Role(null, defaultRoleName)));
    }
}
