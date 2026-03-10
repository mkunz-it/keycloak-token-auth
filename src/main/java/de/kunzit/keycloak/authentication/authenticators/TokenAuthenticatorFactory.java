package de.kunzit.keycloak.authentication.authenticators;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class TokenAuthenticatorFactory
    implements AuthenticatorFactory, ServerInfoAwareProviderFactory
{

    public static final String FORM_PARAM_NAME         = "formParamName";
    public static final String FORM_PARAM_NAME_DEFAULT = "id_token";

    public static final String PROPERTY_AUDIENCE                 = "expectedAudience";
    public static final String PROPERTY_AZP                      = "expectedAzp";
    public static final String PROPERTY_OFFLINE_SESSIONS_ALLOWED = "offlineSessionsAllowed";

    public static final String PROVIDER_ID = "token-authenticator";

    private static final TokenAuthenticator SINGLETON = new TokenAuthenticator();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override public String getDisplayType()
    {
        return "ID Token Authentication";
    }

    @Override public String getReferenceCategory()
    {
        return "token";
    }

    @Override public boolean isConfigurable()
    {
        return true;
    }

    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices()
    {
        return REQUIREMENT_CHOICES;
    }

    @Override public boolean isUserSetupAllowed()
    {
        return true;
    }

    @Override public String getHelpText()
    {
        return "Identify users based on existing ID tokens";
    }

    @Override public List<ProviderConfigProperty> getConfigProperties()
    {
        return Arrays.asList(
            new ProviderConfigProperty(FORM_PARAM_NAME, "Form parameter", "Name of the form parameter to search for an ID token",
                                       ProviderConfigProperty.STRING_TYPE,
                                       FORM_PARAM_NAME_DEFAULT, false, true),
            new ProviderConfigProperty(PROPERTY_AUDIENCE, "Audience", "Expected audience for the ID Token",
                                       ProviderConfigProperty.CLIENT_LIST_TYPE, null, false, true),
            new ProviderConfigProperty(PROPERTY_AZP, "Issued For", "Expected 'azp' claim (issued for) for the ID Token",
                                       ProviderConfigProperty.CLIENT_LIST_TYPE, null, false, true),
            new ProviderConfigProperty(PROPERTY_OFFLINE_SESSIONS_ALLOWED, "Offline sessions allowed",
                                       "Additionally searches for an offline session based on the Session-ID (sid).",
                                       ProviderConfigProperty.BOOLEAN_TYPE, "true")
        );
    }

    @Override public Authenticator create(KeycloakSession keycloakSession)
    {
        return SINGLETON;
    }

    @Override public void init(Config.Scope scope)
    {
        //nothing to initialize
    }

    @Override public void postInit(KeycloakSessionFactory keycloakSessionFactory)
    {
        //nothing to initialize
    }

    @Override public void close()
    {
        //nothing to close
    }

    @Override public String getId()
    {
        return PROVIDER_ID;
    }

    @Override public Map<String, String> getOperationalInfo()
    {
        String version = TokenAuthenticatorFactory.class.getPackage().getImplementationVersion();
        if (version == null) {
            version = "unknown";
        }
        return Map.of("Version", version);
    }
}
