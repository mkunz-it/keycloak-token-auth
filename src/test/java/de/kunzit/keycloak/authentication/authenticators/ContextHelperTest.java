package de.kunzit.keycloak.authentication.authenticators;

import de.kunzit.keycloak.authentication.authenticators.helper.ContextHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.VerificationException;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.TokenUtil;
import org.mockito.MockedStatic;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.notNull;
import static org.mockito.Mockito.*;

@ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class ContextHelperTest {

    private AuthenticationFlowContext  flowContext;
    private AuthenticatorConfigModel   authenticatorConfigModel;
    private AuthenticationSessionModel authenticationSession;
    private KeycloakSession            session;
    private KeycloakContext            keycloakContext;
    private RealmModel                 realm;
    private UserProvider               userProvider;
    private UserSessionProvider        userSessionProvider;

    private Map<String, String> config;

    @BeforeEach
    void setUp()
    {
        flowContext = mock(AuthenticationFlowContext.class);
        authenticatorConfigModel = mock(AuthenticatorConfigModel.class);
        authenticationSession = mock(AuthenticationSessionModel.class);
        session = mock(KeycloakSession.class);
        keycloakContext = mock(KeycloakContext.class);
        realm = mock(RealmModel.class);
        userProvider = mock(UserProvider.class);
        userSessionProvider = mock(UserSessionProvider.class);

        config = new HashMap<>();
        config.put(TokenAuthenticatorFactory.FORM_PARAM_NAME, "id_token");
        config.put(TokenAuthenticatorFactory.PROPERTY_AUDIENCE, "my-audience");
        config.put(TokenAuthenticatorFactory.PROPERTY_AZP, "my-client");
        config.put(TokenAuthenticatorFactory.PROPERTY_OFFLINE_SESSIONS_ALLOWED, "true");
        config.put(TokenAuthenticatorFactory.PROPERTY_ACCESS_TOKEN_ALLOWED, "false");

        when(authenticatorConfigModel.getConfig()).thenReturn(config);
        when(flowContext.getAuthenticatorConfig()).thenReturn(authenticatorConfigModel);
        when(flowContext.getAuthenticationSession()).thenReturn(authenticationSession);
        when(flowContext.getSession()).thenReturn(session);
        when(flowContext.getRealm()).thenReturn(realm);
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);
        when(session.sessions()).thenReturn(userSessionProvider);
    }

    @Test
    void shouldReturnConfiguredValuesAndRawToken()
    {
        when(authenticationSession.getClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + "id_token"))
            .thenReturn("raw-token");

        ContextHelper helper = ContextHelper.getInstance(flowContext);

        assertThat(helper.getExpectedAudience()).isEqualTo("my-audience");
        assertThat(helper.getIssuedFor()).isEqualTo("my-client");
        assertThat(helper.getFormParameter()).isEqualTo("id_token");
        assertThat(helper.getRawToken()).isEqualTo("raw-token");
        assertThat(helper.isOfflineSessionsAllowed()).isTrue();
        assertThat(helper.isAccessTokenAllowed()).isFalse();
    }

    @Test
    void shouldResolveExpectedIssuerFromRealmAndAuthServerUrl()
    {
        when(keycloakContext.getAuthServerUrl()).thenReturn(URI.create("https://sso.example.test/auth"));
        when(realm.getName()).thenReturn("my-realm");

        ContextHelper helper = ContextHelper.getInstance(flowContext);

        assertThat(helper.getExpectedIssuer()).isEqualTo("https://sso.example.test/auth/realms/my-realm");
    }

    @Test
    void shouldBuildTokenVerifierChecksWithOptionalChecksWhenConfigured()
    {
        when(keycloakContext.getAuthServerUrl()).thenReturn(URI.create("https://sso.example.test/auth"));
        when(realm.getName()).thenReturn("my-realm");

        List<TokenVerifier.Predicate<? super IDToken>> checks = ContextHelper.getInstance(flowContext).getTokenVerifierChecks();

        assertThat(checks).hasSize(5);
        assertThat(checks.get(0)).isSameAs(TokenVerifier.IS_ACTIVE);
        assertThat(checks.get(1)).isInstanceOf(TokenVerifier.TokenTypeCheck.class);
        assertThat(checks.get(2)).isInstanceOf(TokenVerifier.AudienceCheck.class);
        assertThat(checks.get(3)).isInstanceOf(TokenVerifier.IssuedForCheck.class);
        assertThat(checks.get(4)).isInstanceOf(TokenVerifier.RealmUrlCheck.class);
    }

    @Test
    void shouldSkipOptionalChecksWhenAudienceAndIssuedForAreMissing()
    {
        config.put(TokenAuthenticatorFactory.PROPERTY_AUDIENCE, " ");
        config.put(TokenAuthenticatorFactory.PROPERTY_AZP, "");
        when(keycloakContext.getAuthServerUrl()).thenReturn(URI.create("https://sso.example.test/auth"));
        when(realm.getName()).thenReturn("my-realm");

        List<TokenVerifier.Predicate<? super IDToken>> checks = ContextHelper.getInstance(flowContext).getTokenVerifierChecks();

        assertThat(checks).hasSize(3);
        assertThat(checks.get(0)).isSameAs(TokenVerifier.IS_ACTIVE);
        assertThat(checks.get(1)).isInstanceOf(TokenVerifier.TokenTypeCheck.class);
        assertThat(checks.get(2)).isInstanceOf(TokenVerifier.RealmUrlCheck.class);
    }

    @Test
    void shouldAddUserToContextAndClearClientNote()
    {
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn("user-id");

        ContextHelper helper = ContextHelper.getInstance(flowContext);
        helper.addUserToContext(user);

        verify(flowContext).setUser(user);
        verify(authenticationSession).setAuthNote(eq("EXISTING_USER_INFO"), notNull());
        verify(authenticationSession).removeClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + "id_token");
    }

    @Test
    void shouldReportSuccessBasedOnFlowStatus()
    {
        when(flowContext.getStatus()).thenReturn(FlowStatus.SUCCESS);
        assertThat(ContextHelper.getInstance(flowContext).isSuccess()).isTrue();

        when(flowContext.getStatus()).thenReturn(FlowStatus.ATTEMPTED);
        assertThat(ContextHelper.getInstance(flowContext).isSuccess()).isFalse();
    }

    @Test
    void shouldGetUserBySessionId()
        throws VerificationException
    {
        String sessionId = "bcdd9603-cabf-4c90-b71e-8a7fcaf6a23f";
        IDToken token = new IDToken();
        token.setSessionId(sessionId);
        UserModel expected = mock(UserModel.class);
        UserSessionModel userSession = mock(UserSessionModel.class);
        when(userSessionProvider.getUserSession(realm, sessionId)).thenReturn(userSession);
        when(userSession.getUser()).thenReturn(expected);
        try (MockedStatic<AuthenticationManager> authManager =
            mockStatic(AuthenticationManager.class)) {

            authManager
                .when(() -> AuthenticationManager.isSessionValid(realm, userSession))
                .thenReturn(true);

            UserModel user = ContextHelper.getInstance(flowContext).getUserBySessionID(token);
            assertThat(user).isSameAs(expected);
        }
    }

    @Test
    void shouldReturnNullIfSessionNotExists()
        throws VerificationException
    {
        String sessionId = "bcdd9603-cabf-4c90-b71e-8a7fcaf6a23f";
        IDToken token = new IDToken();
        token.setSessionId(sessionId);
        UserModel expected = mock(UserModel.class);
        UserSessionModel userSession = mock(UserSessionModel.class);
        when(userSessionProvider.getUserSession(realm, sessionId)).thenReturn(null);
        when(userSessionProvider.getOfflineUserSession(realm, sessionId)).thenReturn(null);
        when(userSession.getUser()).thenReturn(expected);

        try (MockedStatic<AuthenticationManager> authManager =
            mockStatic(AuthenticationManager.class)) {

            authManager
                .when(() -> AuthenticationManager.isSessionValid(eq(realm), isNull()))
                .thenReturn(false);

            UserModel user = ContextHelper.getInstance(flowContext).getUserBySessionID(token);
            assertThat(user).isNull();
        }
    }

    @Test
    void shouldGetUserBySessionIdOffline()
        throws VerificationException
    {
        String sessionId = "bcdd9603-cabf-4c90-b71e-8a7fcaf6a23f";
        config.put(TokenAuthenticatorFactory.PROPERTY_OFFLINE_SESSIONS_ALLOWED, "true");
        IDToken token = new IDToken();
        token.setSessionId(sessionId);
        UserModel expected = mock(UserModel.class);
        UserSessionModel userSession = mock(UserSessionModel.class);
        when(userSessionProvider.getUserSession(realm, sessionId)).thenReturn(null);
        when(userSessionProvider.getOfflineUserSession(realm, sessionId)).thenReturn(userSession);
        when(userSession.getUser()).thenReturn(expected);
        try (MockedStatic<AuthenticationManager> authManager =
            mockStatic(AuthenticationManager.class)) {

            authManager
                .when(() -> AuthenticationManager.isSessionValid(eq(realm), isNull()))
                .thenReturn(false);

            authManager
                .when(() -> AuthenticationManager.isSessionValid(eq(realm), eq(userSession)))
                .thenReturn(true);

            UserModel user = ContextHelper.getInstance(flowContext).getUserBySessionID(token);
            assertThat(user).isSameAs(expected);
        }
    }

    @Test
    void shouldReturnNullIfOfflineSessionNotExists()
        throws VerificationException
    {
        String sessionId = "bcdd9603-cabf-4c90-b71e-8a7fcaf6a23f";
        config.put(TokenAuthenticatorFactory.PROPERTY_OFFLINE_SESSIONS_ALLOWED, "true");
        IDToken token = new IDToken();
        token.setSessionId(sessionId);
        UserModel expected = mock(UserModel.class);
        UserSessionModel userSession = mock(UserSessionModel.class);
        when(userSessionProvider.getUserSession(realm, sessionId)).thenReturn(null);
        when(userSessionProvider.getOfflineUserSession(realm, sessionId)).thenReturn(null);
        when(userSession.getUser()).thenReturn(expected);

        try (MockedStatic<AuthenticationManager> authManager =
            mockStatic(AuthenticationManager.class)) {

            authManager
                .when(() -> AuthenticationManager.isSessionValid(eq(realm), isNull()))
                .thenReturn(false);

            UserModel user = ContextHelper.getInstance(flowContext).getUserBySessionID(token);
            assertThat(user).isNull();
        }
    }

    @Test
    void shouldReturnNullIfOfflineSessionExistsButNotAllowed()
        throws VerificationException
    {
        String sessionId = "bcdd9603-cabf-4c90-b71e-8a7fcaf6a23f";
        config.put(TokenAuthenticatorFactory.PROPERTY_OFFLINE_SESSIONS_ALLOWED, "false");
        IDToken token = new IDToken();
        token.setSessionId(sessionId);
        UserModel expected = mock(UserModel.class);
        UserSessionModel userSession = mock(UserSessionModel.class);
        when(userSessionProvider.getUserSession(realm, sessionId)).thenReturn(null);
        when(userSessionProvider.getOfflineUserSession(realm, sessionId)).thenReturn(userSession);
        when(userSession.getUser()).thenReturn(expected);
        UserModel user = ContextHelper.getInstance(flowContext).getUserBySessionID(token);
        assertThat(user).isNull();
    }

    @Test
    void shouldReportUserLockStatusFromBruteForceProtector()
    {
        BruteForceProtector protector = mock(BruteForceProtector.class);
        UserModel user = mock(UserModel.class);

        when(realm.isBruteForceProtected()).thenReturn(true);
        when(session.getProvider(BruteForceProtector.class)).thenReturn(protector);
        when(protector.isPermanentlyLockedOut(session, realm, user)).thenReturn(false);
        when(protector.isTemporarilyDisabled(session, realm, user)).thenReturn(true);

        boolean locked = ContextHelper.getInstance(flowContext).isUserLocked(user);

        assertThat(locked).isTrue();
    }

    @Test
    void shouldReturnFalseForLockWhenProtectionDisabled()
    {
        when(realm.isBruteForceProtected()).thenReturn(false);

        boolean locked = ContextHelper.getInstance(flowContext).isUserLocked(mock(UserModel.class));

        assertThat(locked).isFalse();
        verify(session, never()).getProvider(BruteForceProtector.class);
    }

    @Test
    void shouldAcceptAccessTokenWhenItIsAllowed()
        throws VerificationException
    {
        config.put(TokenAuthenticatorFactory.PROPERTY_AUDIENCE, " ");
        config.put(TokenAuthenticatorFactory.PROPERTY_AZP, "");
        config.put(TokenAuthenticatorFactory.PROPERTY_OFFLINE_SESSIONS_ALLOWED, "true");
        config.put(TokenAuthenticatorFactory.PROPERTY_ACCESS_TOKEN_ALLOWED, "true");
        when(keycloakContext.getAuthServerUrl()).thenReturn(URI.create("https://sso.example.test/auth"));
        when(realm.getName()).thenReturn("my-realm");

        AccessToken accessToken = new AccessToken();
        accessToken.type(TokenUtil.TOKEN_TYPE_BEARER);

        List<TokenVerifier.Predicate<? super IDToken>> checks = ContextHelper.getInstance(flowContext).getTokenVerifierChecks();
        assertThat(checks).hasSize(3);
        assertThat(checks.get(1)).isInstanceOf(TokenVerifier.TokenTypeCheck.class);
        TokenVerifier.TokenTypeCheck tokenTypeCheck = (TokenVerifier.TokenTypeCheck)checks.get(1);
        assertThat(tokenTypeCheck.test(accessToken)).isTrue();
    }

    @Test
    void shouldDenyAccessTokenWhenItIsNotAllowed()
    {
        config.put(TokenAuthenticatorFactory.PROPERTY_AUDIENCE, " ");
        config.put(TokenAuthenticatorFactory.PROPERTY_AZP, "");
        config.put(TokenAuthenticatorFactory.PROPERTY_OFFLINE_SESSIONS_ALLOWED, "true");
        config.put(TokenAuthenticatorFactory.PROPERTY_ACCESS_TOKEN_ALLOWED, "false");
        when(keycloakContext.getAuthServerUrl()).thenReturn(URI.create("https://sso.example.test/auth"));
        when(realm.getName()).thenReturn("my-realm");

        AccessToken accessToken = new AccessToken();
        accessToken.type(TokenUtil.TOKEN_TYPE_BEARER);

        List<TokenVerifier.Predicate<? super IDToken>> checks = ContextHelper.getInstance(flowContext).getTokenVerifierChecks();
        assertThat(checks).hasSize(3);
        assertThat(checks.get(1)).isInstanceOf(TokenVerifier.TokenTypeCheck.class);
        TokenVerifier.TokenTypeCheck tokenTypeCheck = (TokenVerifier.TokenTypeCheck)checks.get(1);
        assertThatThrownBy(() -> tokenTypeCheck.test(accessToken))
            .isInstanceOf(VerificationException.class)
            .hasMessage("Token type is incorrect. Expected '[ID]' but was 'Bearer'");
    }
}
