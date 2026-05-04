package de.kunzit.keycloak.authentication.authenticators;

import de.kunzit.keycloak.authentication.authenticators.helper.ContextHelper;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenAuthenticator
    implements Authenticator
{

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenAuthenticator.class);

    @Override public void authenticate(AuthenticationFlowContext context)
    {
        ContextHelper helper = ContextHelper.getInstance(context);
        if (helper.isConfidentialClient()) {
            String rawIdToken = helper.getRawToken();

            if (rawIdToken != null && !rawIdToken.isEmpty()) {
                try {
                    IDToken token = validateToken(context, rawIdToken, helper);
                    UserModel user = helper.getUserBySessionID(token);
                    if (isValidUser(helper, user)) {
                        helper.addUserToContext(user);
                        context.success();
                    }
                } catch (VerificationException e) {
                    LOGGER.info("Invalid token was used for authentication - {}", e.getMessage());
                }
            }
            else {
                LOGGER.debug("Could not find ID Token for form parameter {}", helper.getFormParameter());
            }
        } else {
            LOGGER.warn("!!! TokenAuthenticator” is only permitted for confidential clients – execution skipped !!!");
        }

        if (!helper.isSuccess()) {
            context.attempted();
        }
    }

    private IDToken validateToken(AuthenticationFlowContext context, String rawIdToken, ContextHelper helper)
        throws VerificationException
    {
        // 1) Parse (no checks yet)
        TokenVerifier<IDToken> verifier = TokenVerifier.create(rawIdToken, IDToken.class)
                                                       .parse();
        JWSHeader header = verifier.getHeader();
        if (header == null)
            throw new VerificationException("Missing JWS header");

        // 2) Build signature verifier based on token header (alg + kid)
        String alg = header.getRawAlgorithm();
        String kid = header.getKeyId();

        if (alg == null || kid == null) {
            throw new VerificationException("Missing alg/kid in header");
        }

        SignatureProvider sigProvider = context.getSession().getProvider(SignatureProvider.class, alg);
        if (sigProvider == null)
            throw new VerificationException("No SignatureProvider for alg=" + alg);

        SignatureVerifierContext sigVerifier = sigProvider.verifier(kid);
        verifier.verifierContext(sigVerifier);
        verifier.withChecks(helper.getTokenVerifierChecks().toArray(new TokenVerifier.Predicate[0])).verify();
        return verifier.getToken();
    }

    private boolean isValidUser(ContextHelper helper, UserModel user)
    {
        return user != null && user.isEnabled() && !helper.isUserLocked(user);
    }

    @Override public void action(AuthenticationFlowContext authenticationFlowContext)
    {
        // never called
    }

    @Override public boolean requiresUser()
    {
        return false;
    }

    @Override public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel)
    {
        // never called
        return true;
    }

    @Override public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel)
    {
        // never called
    }

    @Override public void close()
    {
        //nothing to close
    }
}
