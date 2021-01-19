package com.ayc.keycloaksecurity.util;

import com.ayc.exceptionhandler.config.EnableAycExceptionHandling;
import com.ayc.exceptionhandler.exception.NotAuthorizedException;
import com.ayc.keycloaksecurity.consts.ErrorConst;
import com.ayc.keycloaksecurity.consts.SecurityConst;
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
@EnableAycExceptionHandling
public class SecurityUtil {

    @Autowired
    private HttpServletRequest request;

    public KeycloakAuthenticationToken getPrincipal() {
        KeycloakAuthenticationToken principal = (KeycloakAuthenticationToken) request.getUserPrincipal();
        if (principal == null) {
            throw new AuthenticationServiceException(ErrorConst.NO_USER_FOUND);
        }
        return principal;
    }

    public AccessToken getAccessToken() {
        return getPrincipal().getAccount().getKeycloakSecurityContext().getToken();
    }

    public String getKeycloakId() {
        return getAccessToken().getId();
    }

    public String getUsername() {
        return getAccessToken().getPreferredUsername();
    }

    public String getFullName() {
        return getAccessToken().getName();
    }

    public String getEmail() {
        return getAccessToken().getEmail();
    }

    public boolean isAdminOrUser(String username) throws NotAuthorizedException {
        if (getUsername().equals(username) || isAdmin()) {
            return true;
        } else {
            throw new NotAuthorizedException(ErrorConst.NOT_AUTHORIZED);
        }
    }

    public boolean isAdmin() {
        return getAccessToken().getRealmAccess().getRoles().stream().anyMatch(role -> role.equals(SecurityConst.ADMIN_ROLE));
    }
}
