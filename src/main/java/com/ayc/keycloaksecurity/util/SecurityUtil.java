package com.ayc.keycloaksecurity.util;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
@Primary
public class SecurityUtil {

    @Autowired
    private HttpServletRequest request;

    public KeycloakAuthenticationToken getPrincipal() {
        KeycloakAuthenticationToken principal = (KeycloakAuthenticationToken) request.getUserPrincipal();
        if (principal == null) {
            throw new AuthenticationServiceException(
                    "No user details found, while trying to access user principal. Check if user is logged in and authentication is required.");
        }
        return principal;
    }

    public AccessToken getAccessToken() {
        return getPrincipal().getAccount().getKeycloakSecurityContext().getToken();
    }

    public String getUsername() {
        return getAccessToken().getName();
    }

    public String getKeycloakId() {
        return getAccessToken().getId();
    }

    public String getEmail() {
        return getAccessToken().getEmail();
    }

    public boolean isAdminOrUser(String username) {
        if (getUsername().equals(username) || isAdmin()) {
            return true;
        } else {
            throw new AuthorizationDeniedException(new Throwable("Zugriff verweigert"));
        }
    }

    public boolean isAdmin() {
        return getAccessToken().getRealmAccess().equals("admin");
    }
}
