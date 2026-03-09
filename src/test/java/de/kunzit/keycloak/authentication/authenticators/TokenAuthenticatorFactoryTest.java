package de.kunzit.keycloak.authentication.authenticators;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class TokenAuthenticatorFactoryTest {

    private final TokenAuthenticatorFactory factory = new TokenAuthenticatorFactory();

    @Test
    void shouldExposeMetadata()
    {
        assertThat(factory.getDisplayType()).isEqualTo("ID Token Authentication");
        assertThat(factory.getReferenceCategory()).isEqualTo("token");
        assertThat(factory.getHelpText()).isEqualTo("Identify users based on existing ID tokens");
        assertThat(factory.getId()).isEqualTo(TokenAuthenticatorFactory.PROVIDER_ID);
    }

    @Test
    void shouldExposeExecutionFlagsAndRequirements()
    {
        assertThat(factory.isConfigurable()).isTrue();
        assertThat(factory.isUserSetupAllowed()).isTrue();

        assertThat(factory.getRequirementChoices())
            .containsExactly(
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
            );
    }

    @Test
    void shouldExposeConfigProperties()
    {
        List<ProviderConfigProperty> props = factory.getConfigProperties();

        assertThat(props).hasSize(4);
        assertThat(props).extracting(ProviderConfigProperty::getName)
                         .containsExactly(
                             TokenAuthenticatorFactory.FORM_PARAM_NAME,
                             TokenAuthenticatorFactory.PROPERTY_AUDIENCE,
                             TokenAuthenticatorFactory.PROPERTY_AZP,
                             TokenAuthenticatorFactory.PROPERTY_OFFLINE_SESSIONS_ALLOWED
                         );
    }

    @Test
    void shouldReturnSingletonAuthenticator()
    {
        Authenticator first = factory.create(null);
        Authenticator second = factory.create(null);

        assertThat(first).isSameAs(second).isInstanceOf(TokenAuthenticator.class);
    }

    @Test
    void shouldReturnOperationalInfoWithVersionKey()
    {
        Map<String, String> operationalInfo = factory.getOperationalInfo();

        assertThat(operationalInfo).containsKey("Version");
        assertThat(operationalInfo.get("Version")).isNotBlank();
    }
}
