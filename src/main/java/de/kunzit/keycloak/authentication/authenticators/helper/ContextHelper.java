package de.kunzit.keycloak.authentication.authenticators.helper;

import de.kunzit.keycloak.authentication.authenticators.TokenAuthenticatorFactory;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.function.Function;

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

    private String getUserClaim()
    {
        return context.getAuthenticatorConfig().getConfig().get(TokenAuthenticatorFactory.PROPERTY_USER_CLAIM);
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

    public UserModel getUserFromToken(IDToken token)
        throws VerificationException
    {
        UserModel user;
        String userClaim = getUserClaim();
        if (IDToken.PREFERRED_USERNAME.equals(userClaim)) {
            LOGGER.debug(Constants.FETCH_USER_BY, userClaim);
            user = context.getSession().users().getUserByUsername(context.getRealm(), valueOrException(token, IDToken::getPreferredUsername,
                                                                                                       IDToken.PREFERRED_USERNAME));
        }
        else if (IDToken.EMAIL.equals(userClaim)) {
            LOGGER.debug(Constants.FETCH_USER_BY, userClaim);
            user = context.getSession().users().getUserByEmail(context.getRealm(), valueOrException(token, IDToken::getEmail,
                                                                                                    IDToken.EMAIL));
        }
        else if (JsonWebToken.SUBJECT.equals(userClaim)) {
            LOGGER.debug(Constants.FETCH_USER_BY, userClaim);
            user = context.getSession().users()
                          .getUserById(context.getRealm(), valueOrException(token, IDToken::getSubject, JsonWebToken.SUBJECT));
        }
        else {
            throw new VerificationException("Unsupported user claim " + userClaim);
        }
        return user;
    }

    private <T, R> R valueOrException(T obj, Function<T, R> fn, String claim)
        throws VerificationException
    {
        R value = fn.apply(obj);
        if (value == null || (value instanceof String s && s.isBlank())) {
            throw new VerificationException(String.format(Constants.MISSING_CLAIM, claim));
        }
        return value;
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

    public boolean hasActiveClientSession(UserModel user, String issuedFor)
    {
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        ClientModel client = realm.getClientByClientId(issuedFor);
        if (client == null) {
            return false;
        }
        return session.sessions().getUserSessionsStream(realm, user).anyMatch(us -> {
            if (us.getState() != UserSessionModel.State.LOGGED_IN)
                return false;
            if (!AuthenticationManager.isSessionValid(realm, us))
                return false;

            // online client session exists?
            AuthenticatedClientSessionModel cs = session.sessions().getClientSession(us, client, false);
            return AuthenticationManager.isClientSessionValid(realm, client, us, cs);
        });
    }

}
