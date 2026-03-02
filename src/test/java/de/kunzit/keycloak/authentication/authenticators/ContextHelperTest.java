package de.kunzit.keycloak.authentication.authenticators;

import de.kunzit.keycloak.authentication.authenticators.helper.ContextHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.VerificationException;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.representations.IDToken;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class ContextHelperTest {

    private AuthenticationFlowContext flowContext;
    private AuthenticatorConfigModel authenticatorConfigModel;
    private AuthenticationSessionModel authenticationSession;
    private KeycloakSession session;
    private KeycloakContext keycloakContext;
    private RealmModel realm;
    private UserProvider userProvider;

    private Map<String, String> config;

    @BeforeEach
    void setUp() {
        flowContext = mock(AuthenticationFlowContext.class);
        authenticatorConfigModel = mock(AuthenticatorConfigModel.class);
        authenticationSession = mock(AuthenticationSessionModel.class);
        session = mock(KeycloakSession.class);
        keycloakContext = mock(KeycloakContext.class);
        realm = mock(RealmModel.class);
        userProvider = mock(UserProvider.class);

        config = new HashMap<>();
        config.put(TokenAuthenticatorFactory.FORM_PARAM_NAME, "id_token");
        config.put(TokenAuthenticatorFactory.PROPERTY_AUDIENCE, "my-audience");
        config.put(TokenAuthenticatorFactory.PROPERTY_AZP, "my-client");
        config.put(TokenAuthenticatorFactory.PROPERTY_USER_CLAIM, IDToken.PREFERRED_USERNAME);

        when(authenticatorConfigModel.getConfig()).thenReturn(config);
        when(flowContext.getAuthenticatorConfig()).thenReturn(authenticatorConfigModel);
        when(flowContext.getAuthenticationSession()).thenReturn(authenticationSession);
        when(flowContext.getSession()).thenReturn(session);
        when(flowContext.getRealm()).thenReturn(realm);
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);
    }

    @Test
    void shouldReturnConfiguredValuesAndRawToken() {
        when(authenticationSession.getClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + "id_token"))
            .thenReturn("raw-token");

        ContextHelper helper = ContextHelper.getInstance(flowContext);

        assertThat(helper.getExpectedAudience()).isEqualTo("my-audience");
        assertThat(helper.getIssuedFor()).isEqualTo("my-client");
        assertThat(helper.getFormParameter()).isEqualTo("id_token");
        assertThat(helper.getRawToken()).isEqualTo("raw-token");
    }

    @Test
    void shouldResolveExpectedIssuerFromRealmAndAuthServerUrl() {
        when(keycloakContext.getAuthServerUrl()).thenReturn(URI.create("https://sso.example.test/auth"));
        when(realm.getName()).thenReturn("my-realm");

        ContextHelper helper = ContextHelper.getInstance(flowContext);

        assertThat(helper.getExpectedIssuer()).isEqualTo("https://sso.example.test/auth/realms/my-realm");
    }

    @Test
    void shouldAddUserToContextAndClearClientNote() {
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn("user-id");

        ContextHelper helper = ContextHelper.getInstance(flowContext);
        helper.addUserToContext(user);

        verify(flowContext).setUser(user);
        verify(authenticationSession).setAuthNote(eq("EXISTING_USER_INFO"), notNull());
        verify(authenticationSession).removeClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + "id_token");
    }

    @Test
    void shouldReportSuccessBasedOnFlowStatus() {
        when(flowContext.getStatus()).thenReturn(FlowStatus.SUCCESS);
        assertThat(ContextHelper.getInstance(flowContext).isSuccess()).isTrue();

        when(flowContext.getStatus()).thenReturn(FlowStatus.ATTEMPTED);
        assertThat(ContextHelper.getInstance(flowContext).isSuccess()).isFalse();
    }

    @Test
    void shouldGetUserByUsernameClaim() throws VerificationException {
        IDToken token = new IDToken();
        token.setPreferredUsername("alice");
        UserModel expected = mock(UserModel.class);
        when(userProvider.getUserByUsername(realm, "alice")).thenReturn(expected);

        UserModel user = ContextHelper.getInstance(flowContext).getUserFromToken(token);

        assertThat(user).isSameAs(expected);
    }

    @Test
    void shouldGetUserByEmailClaim() throws VerificationException {
        config.put(TokenAuthenticatorFactory.PROPERTY_USER_CLAIM, IDToken.EMAIL);
        IDToken token = new IDToken();
        token.setEmail("alice@example.test");
        UserModel expected = mock(UserModel.class);
        when(userProvider.getUserByEmail(realm, "alice@example.test")).thenReturn(expected);

        UserModel user = ContextHelper.getInstance(flowContext).getUserFromToken(token);

        assertThat(user).isSameAs(expected);
    }

    @Test
    void shouldGetUserBySubjectClaim() throws VerificationException {
        config.put(TokenAuthenticatorFactory.PROPERTY_USER_CLAIM, IDToken.SUBJECT);
        IDToken token = new IDToken();
        token.setSubject("12345");
        UserModel expected = mock(UserModel.class);
        when(userProvider.getUserById(realm, "12345")).thenReturn(expected);

        UserModel user = ContextHelper.getInstance(flowContext).getUserFromToken(token);

        assertThat(user).isSameAs(expected);
    }

    @Test
    void shouldFailWhenClaimIsMissing() {
        IDToken token = new IDToken();

        assertThatThrownBy(() -> ContextHelper.getInstance(flowContext).getUserFromToken(token))
            .isInstanceOf(VerificationException.class)
            .hasMessageContaining("preferred_username claim is missing in token");
    }

    @Test
    void shouldFailOnUnsupportedUserClaim() {
        config.put(TokenAuthenticatorFactory.PROPERTY_USER_CLAIM, "custom-claim");
        IDToken token = new IDToken();

        assertThatThrownBy(() -> ContextHelper.getInstance(flowContext).getUserFromToken(token))
            .isInstanceOf(VerificationException.class)
            .hasMessageContaining("Unsupported user claim custom-claim");
    }

    @Test
    void shouldReportUserLockStatusFromBruteForceProtector() {
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
    void shouldReturnFalseForLockWhenProtectionDisabled() {
        when(realm.isBruteForceProtected()).thenReturn(false);

        boolean locked = ContextHelper.getInstance(flowContext).isUserLocked(mock(UserModel.class));

        assertThat(locked).isFalse();
        verify(session, never()).getProvider(BruteForceProtector.class);
    }

    @Test
    void shouldReturnFalseWhenNoMatchingClientForActiveSessionCheck() {
        UserModel user = mock(UserModel.class);
        when(realm.getClientByClientId("missing-client")).thenReturn(null);

        boolean hasSession = ContextHelper.getInstance(flowContext).hasActiveClientSession(user, "missing-client");

        assertThat(hasSession).isFalse();
    }

    @Test
    void shouldReturnFalseWhenUserHasNoSessionsForClient() {
        UserModel user = mock(UserModel.class);
        ClientModel client = mock(ClientModel.class);
        UserSessionProvider userSessionProvider = mock(UserSessionProvider.class);

        when(realm.getClientByClientId("my-client")).thenReturn(client);
        when(session.sessions()).thenReturn(userSessionProvider);
        when(userSessionProvider.getUserSessionsStream(realm, user)).thenReturn(Stream.empty());

        boolean hasSession = ContextHelper.getInstance(flowContext).hasActiveClientSession(user, "my-client");

        assertThat(hasSession).isFalse();
    }
}
