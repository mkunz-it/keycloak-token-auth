package de.kunzit.keycloak.authentication.authenticators;

import de.kunzit.keycloak.authentication.authenticators.helper.ContextHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.exceptions.TokenNotActiveException;
import org.keycloak.exceptions.TokenSignatureInvalidException;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.IDToken;
import org.keycloak.util.TokenUtil;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class TokenAuthenticatorTest {

    private final TokenAuthenticator authenticator = new TokenAuthenticator();

    @Test
    void shouldAttemptWhenNoTokenWasProvided()
    {
        AuthenticationFlowContext flowContext = mock(AuthenticationFlowContext.class);
        var authenticatorConfig = mock(org.keycloak.models.AuthenticatorConfigModel.class);
        var authSession = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
        var session = mock(KeycloakSession.class);

        when(flowContext.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getConfig()).thenReturn(java.util.Map.of(TokenAuthenticatorFactory.FORM_PARAM_NAME, "id_token"));
        when(flowContext.getAuthenticationSession()).thenReturn(authSession);
        when(flowContext.getSession()).thenReturn(session);
        when(flowContext.getStatus()).thenReturn(FlowStatus.ATTEMPTED);
        when(authSession.getClientNote(anyString())).thenReturn(null);

        authenticator.authenticate(flowContext);

        verify(flowContext).attempted();
        verify(flowContext, never()).success();
    }

    @Test
    void shouldNotAttemptAgainWhenFlowAlreadySucceeded()
    {
        AuthenticationFlowContext flowContext = mock(AuthenticationFlowContext.class);
        var authenticatorConfig = mock(org.keycloak.models.AuthenticatorConfigModel.class);
        var authSession = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
        var session = mock(KeycloakSession.class);

        when(flowContext.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getConfig()).thenReturn(java.util.Map.of(TokenAuthenticatorFactory.FORM_PARAM_NAME, "id_token"));
        when(flowContext.getAuthenticationSession()).thenReturn(authSession);
        when(flowContext.getSession()).thenReturn(session);
        when(flowContext.getStatus()).thenReturn(FlowStatus.SUCCESS);
        when(authSession.getClientNote(anyString())).thenReturn("");

        authenticator.authenticate(flowContext);

        verify(flowContext, never()).attempted();
        verify(flowContext, never()).success();
    }

    @Test
    void shouldExposeAuthenticatorContractDefaults()
    {
        assertThat(authenticator.requiresUser()).isFalse();
        assertThat(authenticator.configuredFor(mock(KeycloakSession.class), mock(RealmModel.class), mock(UserModel.class))).isTrue();
    }

    @Test
    void shouldValidateUserRulesViaPrivateMethod()
        throws Exception
    {
        Method method = TokenAuthenticator.class.getDeclaredMethod("isValidUser", ContextHelper.class, UserModel.class);
        method.setAccessible(true);

        ContextHelper helper = mock(ContextHelper.class);
        UserModel user = mock(UserModel.class);
        when(user.isEnabled()).thenReturn(true);
        when(helper.isUserLocked(user)).thenReturn(false);

        boolean result = (boolean)method.invoke(authenticator, helper, user);

        assertThat(result).isTrue();
    }

    @Test
    void shouldAcceptIdTokenWithValidSignature()
        throws Exception
    {
        String kid = "kid-valid";
        String issuer = "http://localhost/realms/demo";
        String audience = "account-console";
        String issuedFor = "mobile-app";

        KeyPair keyPair = generateRsaKeyPair();
        String rawToken = createSignedIdToken(keyPair, kid, issuer, audience, issuedFor);
        AuthenticationFlowContext flowContext = flowContextWithVerifierKey(kid, keyPair);
        ContextHelper helper = helper(issuer, audience, issuedFor);

        IDToken token = (IDToken)validateTokenMethod().invoke(authenticator, flowContext, rawToken, helper);

        assertThat(token.getIssuer()).isEqualTo(issuer);
        assertThat(token.getIssuedFor()).isEqualTo(issuedFor);
        assertThat(token.hasAudience(audience)).isTrue();
    }

    @Test
    void shouldRejectIdTokenWithInvalidSignature()
        throws Exception
    {
        String kid = "kid-invalid";
        String issuer = "http://localhost/realms/demo";
        String audience = "account-console";
        String issuedFor = "mobile-app";

        KeyPair signingKey = generateRsaKeyPair();
        KeyPair verifierKey = generateRsaKeyPair();
        String rawToken = createSignedIdToken(signingKey, kid, issuer, audience, issuedFor);
        AuthenticationFlowContext flowContext = flowContextWithVerifierKey(kid, verifierKey);
        ContextHelper helper = helper(issuer, audience, issuedFor);

        Method validate = validateTokenMethod();
        assertThatThrownBy(() -> validate.invoke(authenticator, flowContext, rawToken, helper))
            .hasCauseInstanceOf(VerificationException.class)
            .rootCause()
            .isInstanceOf(TokenSignatureInvalidException.class);
    }

    @Test
    void shouldRejectInactiveToken()
        throws Exception
    {
        String kid = "kid-inactive";
        String issuer = "http://localhost/realms/demo";
        String audience = "account-console";
        String issuedFor = "mobile-app";

        KeyPair keyPair = generateRsaKeyPair();
        String rawToken = createSignedIdToken(keyPair, kid, issuer, audience, issuedFor, TokenUtil.TOKEN_TYPE_ID,
                                              Instant.now().getEpochSecond() - 60);
        AuthenticationFlowContext flowContext = flowContextWithVerifierKey(kid, keyPair);
        ContextHelper helper = helper(issuer, audience, issuedFor);

        VerificationException verificationException = invokeValidateExpectingVerification(flowContext, rawToken, helper);
        assertThat(verificationException).isInstanceOf(TokenNotActiveException.class).hasMessageContaining("Token is not active");
    }

    @Test
    void shouldRejectTokenWithWrongType()
        throws Exception
    {
        String kid = "kid-wrong-type";
        String issuer = "http://localhost/realms/demo";
        String audience = "account-console";
        String issuedFor = "mobile-app";

        KeyPair keyPair = generateRsaKeyPair();
        String rawToken = createSignedIdToken(keyPair, kid, issuer, audience, issuedFor, "Bearer",
                                              Instant.now().getEpochSecond() + 300);
        AuthenticationFlowContext flowContext = flowContextWithVerifierKey(kid, keyPair);
        ContextHelper helper = helper(issuer, audience, issuedFor);

        VerificationException verificationException = invokeValidateExpectingVerification(flowContext, rawToken, helper);
        assertThat(verificationException).hasMessageContaining("Token type is incorrect");
    }

    @Test
    void shouldRejectTokenWithWrongAudience()
        throws Exception
    {
        String kid = "kid-wrong-audience";
        String issuer = "http://localhost/realms/demo";
        String audienceInToken = "different-audience";
        String expectedAudience = "account-console";
        String issuedFor = "mobile-app";

        KeyPair keyPair = generateRsaKeyPair();
        String rawToken = createSignedIdToken(keyPair, kid, issuer, audienceInToken, issuedFor, TokenUtil.TOKEN_TYPE_ID,
                                              Instant.now().getEpochSecond() + 300);
        AuthenticationFlowContext flowContext = flowContextWithVerifierKey(kid, keyPair);
        ContextHelper helper = helper(issuer, expectedAudience, issuedFor);

        VerificationException verificationException = invokeValidateExpectingVerification(flowContext, rawToken, helper);
        assertThat(verificationException).hasMessageContaining("Expected audience not available in the token");
    }

    @Test
    void shouldRejectTokenWithWrongIssuedFor()
        throws Exception
    {
        String kid = "kid-wrong-issued-for";
        String issuer = "http://localhost/realms/demo";
        String audience = "account-console";
        String issuedForInToken = "other-client";
        String expectedIssuedFor = "mobile-app";

        KeyPair keyPair = generateRsaKeyPair();
        String rawToken = createSignedIdToken(keyPair, kid, issuer, audience, issuedForInToken, TokenUtil.TOKEN_TYPE_ID,
                                              Instant.now().getEpochSecond() + 300);
        AuthenticationFlowContext flowContext = flowContextWithVerifierKey(kid, keyPair);
        ContextHelper helper = helper(issuer, audience, expectedIssuedFor);

        VerificationException verificationException = invokeValidateExpectingVerification(flowContext, rawToken, helper);
        assertThat(verificationException).hasMessageContaining("Expected issuedFor doesn't match");
    }

    @Test
    void shouldRejectTokenWithWrongIssuer()
        throws Exception
    {
        String kid = "kid-wrong-issuer";
        String issuerInToken = "http://localhost/realms/other";
        String expectedIssuer = "http://localhost/realms/demo";
        String audience = "account-console";
        String issuedFor = "mobile-app";

        KeyPair keyPair = generateRsaKeyPair();
        String rawToken = createSignedIdToken(keyPair, kid, issuerInToken, audience, issuedFor, TokenUtil.TOKEN_TYPE_ID,
                                              Instant.now().getEpochSecond() + 300);
        AuthenticationFlowContext flowContext = flowContextWithVerifierKey(kid, keyPair);
        ContextHelper helper = helper(expectedIssuer, audience, issuedFor);

        VerificationException verificationException = invokeValidateExpectingVerification(flowContext, rawToken, helper);
        assertThat(verificationException).hasMessageContaining("Invalid token issuer");
    }

    private static Method validateTokenMethod()
        throws Exception
    {
        Method method = TokenAuthenticator.class.getDeclaredMethod("validateToken", AuthenticationFlowContext.class, String.class,
                                                                   ContextHelper.class);
        method.setAccessible(true);
        return method;
    }

    private VerificationException invokeValidateExpectingVerification(AuthenticationFlowContext flowContext, String rawToken, ContextHelper helper)
        throws Exception
    {
        try {
            validateTokenMethod().invoke(authenticator, flowContext, rawToken, helper);
        } catch (InvocationTargetException e) {
            assertThat(e.getCause()).isInstanceOf(VerificationException.class);
            return (VerificationException)e.getCause();
        }
        throw new AssertionError("Expected validateToken to fail");
    }

    private static ContextHelper helper(String expectedIssuer, String expectedAudience, String issuedFor)
    {
        ContextHelper helper = mock(ContextHelper.class);
        when(helper.getExpectedIssuer()).thenReturn(expectedIssuer);
        when(helper.getExpectedAudience()).thenReturn(expectedAudience);
        when(helper.getIssuedFor()).thenReturn(issuedFor);
        List<TokenVerifier.Predicate<? super IDToken>> checks = new ArrayList<>();
        checks.add(TokenVerifier.IS_ACTIVE);
        checks.add(new TokenVerifier.TokenTypeCheck(List.of(TokenUtil.TOKEN_TYPE_ID)));
        if (expectedAudience != null && !expectedAudience.isBlank()) {
            checks.add(new TokenVerifier.AudienceCheck(expectedAudience));
        }
        if (issuedFor != null && !issuedFor.isBlank()) {
            checks.add(new TokenVerifier.IssuedForCheck(issuedFor));
        }
        checks.add(new TokenVerifier.RealmUrlCheck(expectedIssuer));
        when(helper.getTokenVerifierChecks()).thenReturn(checks);
        return helper;
    }

    private static AuthenticationFlowContext flowContextWithVerifierKey(String kid, KeyPair verifierKey)
        throws VerificationException
    {
        AuthenticationFlowContext flowContext = mock(AuthenticationFlowContext.class);
        KeycloakSession session = mock(KeycloakSession.class);
        SignatureProvider signatureProvider = mock(SignatureProvider.class);

        when(flowContext.getSession()).thenReturn(session);
        when(session.getProvider(SignatureProvider.class, "RS256")).thenReturn(signatureProvider);
        when(signatureProvider.verifier(kid)).thenReturn(verifierContext(kid, verifierKey));
        return flowContext;
    }

    private static AsymmetricSignatureVerifierContext verifierContext(String kid, KeyPair keyPair)
    {
        KeyWrapper key = new KeyWrapper();
        key.setKid(kid);
        key.setAlgorithm("RS256");
        key.setPublicKey(keyPair.getPublic());
        return new AsymmetricSignatureVerifierContext(key);
    }

    private static String createSignedIdToken(KeyPair keyPair, String kid, String issuer, String audience, String issuedFor)
    {
        return createSignedIdToken(keyPair, kid, issuer, audience, issuedFor, TokenUtil.TOKEN_TYPE_ID,
                                   Instant.now().getEpochSecond() + 300);
    }

    private static String createSignedIdToken(KeyPair keyPair, String kid, String issuer, String audience, String issuedFor,
                                              String tokenType, long expEpochSeconds)
    {
        IDToken token = new IDToken();
        token.issuedNow();
        token.exp(expEpochSeconds);
        token.issuer(issuer);
        token.audience(audience);
        token.issuedFor(issuedFor);
        token.type(tokenType);
        token.setSubject("123");
        token.setPreferredUsername("john.doe@example.com");

        KeyWrapper signingKey = new KeyWrapper();
        signingKey.setKid(kid);
        signingKey.setAlgorithm("RS256");
        signingKey.setPrivateKey(keyPair.getPrivate());

        return new JWSBuilder()
            .kid(kid)
            .jsonContent(token)
            .sign(new AsymmetricSignatureSignerContext(signingKey));

    }

    private static KeyPair generateRsaKeyPair()
        throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
