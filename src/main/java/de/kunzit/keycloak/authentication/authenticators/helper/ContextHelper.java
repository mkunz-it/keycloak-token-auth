package de.kunzit.keycloak.authentication.authenticators.helper;

import de.kunzit.keycloak.authentication.authenticators.TokenAuthenticatorFactory;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.representations.IDToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.util.TokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ContextHelper {

    private static final Logger                    LOGGER = LoggerFactory.getLogger(ContextHelper.class);
    private              AuthenticationFlowContext context;

    private ContextHelper(AuthenticationFlowContext context)
    {
        this.context = context;
    }

    public static ContextHelper getInstance(AuthenticationFlowContext context)
    {
        return new ContextHelper(context);
    }

    public boolean isAccessTokenAllowed()
    {
        return Boolean.parseBoolean(
            context.getAuthenticatorConfig().getConfig().getOrDefault(TokenAuthenticatorFactory.PROPERTY_ACCESS_TOKEN_ALLOWED, "false"));
    }

    public String getExpectedAudience()
    {
        return context.getAuthenticatorConfig().getConfig().get(TokenAuthenticatorFactory.PROPERTY_AUDIENCE);
    }

    public String getIssuedFor()
    {
        return context.getAuthenticatorConfig().getConfig().get(TokenAuthenticatorFactory.PROPERTY_AZP);
    }

    public String getRawToken()
    {
        String formParam = getFormParameter();
        return context.getAuthenticationSession().getClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + formParam);
    }

    public String getFormParameter()
    {
        return context.getAuthenticatorConfig().getConfig().get(TokenAuthenticatorFactory.FORM_PARAM_NAME);
    }

    public boolean isOfflineSessionsAllowed()
    {
        return Boolean.parseBoolean(
            context.getAuthenticatorConfig().getConfig().getOrDefault(TokenAuthenticatorFactory.PROPERTY_OFFLINE_SESSIONS_ALLOWED, "false"));
    }

    public String getExpectedIssuer()
    {
        KeycloakContext keycloakContext = context.getSession().getContext();
        RealmModel realm = keycloakContext.getRealm();
        URI authServerUrl = keycloakContext.getAuthServerUrl();
        return KeycloakUriBuilder.fromUri(authServerUrl)
                                 .path("/realms/{realm}")
                                 .build(realm.getName()).toString();
    }

    public List<TokenVerifier.Predicate<? super IDToken>> getTokenVerifierChecks()
    {
        List<TokenVerifier.Predicate<? super IDToken>> checks = new ArrayList<>();
        checks.add(TokenVerifier.IS_ACTIVE);
        List<String> tokenTypes = new ArrayList<>(Arrays.asList(TokenUtil.TOKEN_TYPE_ID));
        if(isAccessTokenAllowed()) {
            tokenTypes.add(TokenUtil.TOKEN_TYPE_BEARER);
        }
        checks.add(new TokenVerifier.TokenTypeCheck(tokenTypes));

        String expectedAudience = getExpectedAudience();
        if (expectedAudience != null && !expectedAudience.isBlank()) {
            checks.add(new TokenVerifier.AudienceCheck(expectedAudience));
        }

        String issuedFor = getIssuedFor();
        if (issuedFor != null && !issuedFor.isBlank()) {
            checks.add(new TokenVerifier.IssuedForCheck(issuedFor));
        }

        checks.add(new TokenVerifier.RealmUrlCheck(getExpectedIssuer()));
        return checks;
    }

    public void addUserToContext(UserModel user)
    {
        ExistingUserInfo userInf = new ExistingUserInfo(user.getId(), null, null);
        context.getAuthenticationSession().setAuthNote(Constants.AUTH_NOTE_EXISTING_USER, userInf.serialize());
        context.setUser(user);
        context.getAuthenticationSession().removeClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + getFormParameter());
    }

    public boolean isSuccess()
    {
        return FlowStatus.SUCCESS.equals(context.getStatus());
    }

    public UserModel getUserBySessionID(IDToken token)
        throws VerificationException
    {
        UserSessionProvider sessions = context.getSession().sessions();
        RealmModel realm = context.getRealm();
        String sessionId = token.getSessionId();
        if (sessionId != null) {
            UserSessionModel userSession = sessions.getUserSession(realm, sessionId);
            if (!AuthenticationManager.isSessionValid(realm, userSession) && isOfflineSessionsAllowed()) {
                userSession = sessions.getOfflineUserSession(realm, sessionId);
            }
            return AuthenticationManager.isSessionValid(realm, userSession) ? userSession.getUser() : null;
        }
        else {
            throw new VerificationException("Session ID not found in ID Token");
        }
    }

    public boolean isUserLocked(UserModel user)
    {
        // Check brute force detection
        if (context.getRealm().isBruteForceProtected()) {
            BruteForceProtector protector = context.getSession().getProvider(BruteForceProtector.class);
            if (protector != null) {
                if (protector.isPermanentlyLockedOut(context.getSession(), context.getRealm(), user)) {
                    LOGGER.debug("User {} is permanently locked out", user.getUsername());
                    return true;
                }
                if (protector.isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                    LOGGER.debug("User {} is temporarily disabled (brute force)", user.getUsername());
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isConfidentialClient(){
        return !context.getAuthenticationSession().getClient().isPublicClient();
    }

}
