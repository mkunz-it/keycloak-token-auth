package de.kunzit.keycloak.authentication.authenticators;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TokenAuthenticatorIntegrationIT {

    private static final String REALM                 = "demo";
    private static final String USERNAME              = "john.doe@example.com";
    private static final String PASSWORD              = "changeIt";
    private static final String SOURCE_CLIENT         = "mobile-app";
    private static final String TARGET_CLIENT_ACCOUNT = "account-console";

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenAuthenticatorIntegrationIT.class);

    @Container
    static final KeycloakContainer KEYCLOAK = FullImageName.createContainer()
                                                           .withLogConsumer(new Slf4jLogConsumer(LOGGER).withSeparateOutputStreams())
                                                           .withRealmImportFile("demo-realm-it.json")
                                                           .withAdminUsername("admin")
                                                           .withAdminPassword("admin")
                                                           .withStartupTimeout(Duration.ofSeconds(90));

    @BeforeAll
    static void setUp()
    {
        LOGGER.info("Running test with Keycloak image: {}", FullImageName.get());
    }

    @Test
    void shouldLoginToAccountConsoleWhenIdTokenContainsAccountConsoleAudience()
        throws Exception
    {
        String idToken = obtainIdToken("openid email account");
        String requestUri = pushedAuthorizationRequest(idToken, TARGET_CLIENT_ACCOUNT, accountConsoleUri().toString());

        try (Playwright playwright = Playwright.create()) {
            Browser browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
            Page page = browser.newContext().newPage();
            page.navigate(browserAuthorizationUri(requestUri));
            assertThat(page.url()).contains("/realms/" + REALM + "/account/");
            page.waitForSelector("input#username");
            String usernameValue = page.locator("input#username").inputValue();
            assertThat(usernameValue).isEqualTo(USERNAME);
            browser.close();
        }
    }

    @Test
    void shouldFailTokenLoginWhenIdTokenHasNoExpectedAudience()
        throws Exception
    {
        String idToken = obtainIdToken("openid email");
        String requestUri = pushedAuthorizationRequest(idToken, TARGET_CLIENT_ACCOUNT, accountConsoleUri().toString());

        try (Playwright playwright = Playwright.create()) {
            Browser browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
            Page page = browser.newContext().newPage();
            page.navigate(browserAuthorizationUri(requestUri));
            assertThat(page.url()).doesNotContain("/realms/" + REALM + "/account/");
            assertThat(page.url()).contains("/realms/" + REALM + "/login-actions/authenticate");
            page.waitForSelector("h1");
            String headline = page.locator("h1").first().textContent();
            assertThat(headline).isNotNull();
            assertThat(headline.trim()).isEqualTo("Sign in to your account");
            page.waitForSelector("input#username");
            page.waitForSelector("input#password");
            assertThat(page.locator("input#username").inputValue()).isEmpty();
            assertThat(page.locator("input#password").inputValue()).isEmpty();
            browser.close();
        }
    }

    @Test
    void shouldLoginToAccountConsoleWhenOfflineSessionIsAllowed()
        throws Exception
    {
        String idToken = obtainIdToken("openid email account offline_access");
        String requestUri = pushedAuthorizationRequest(idToken, TARGET_CLIENT_ACCOUNT, accountConsoleUri().toString());

        try (Playwright playwright = Playwright.create()) {
            Browser browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));
            Page page = browser.newContext().newPage();
            page.navigate(browserAuthorizationUri(requestUri));
            assertThat(page.url()).contains("/realms/" + REALM + "/account/");
            page.waitForSelector("input#username");
            String usernameValue = page.locator("input#username").inputValue();
            assertThat(usernameValue).isEqualTo(USERNAME);
            browser.close();
        }
    }

    private static URI accountConsoleUri()
    {
        return URI.create(baseUrl() + "/realms/" + REALM + "/account/");
    }

    private static String browserAuthorizationUri(String requestUri)
    {
        String authPath = "/realms/" + REALM + "/protocol/openid-connect/auth";
        return baseUrl() + authPath + "?client_id=" + encode(TARGET_CLIENT_ACCOUNT) + "&request_uri=" + encode(requestUri);
    }

    private static String obtainIdToken(String scope)
        throws IOException, InterruptedException
    {
        String tokenPath = "/realms/" + REALM + "/protocol/openid-connect/token";
        Map<String, String> form = new LinkedHashMap<>();
        form.put("client_id", SOURCE_CLIENT);
        form.put("grant_type", "password");
        form.put("username", USERNAME);
        form.put("password", PASSWORD);
        form.put("scope", scope);

        HttpResponse<String> response = postForm(tokenPath, form);
        assertThat(response.statusCode()).isEqualTo(200);

        String idToken = readJsonString(response.body(), "id_token");
        assertThat(idToken).isNotBlank();
        return idToken;
    }

    private static String pushedAuthorizationRequest(String idToken, String targetClient, String redirectUri)
        throws IOException, InterruptedException
    {
        String parPath = "/realms/" + REALM + "/protocol/openid-connect/ext/par/request";
        Map<String, String> form = new LinkedHashMap<>();
        form.put("client_id", targetClient);
        form.put("response_type", "code");
        form.put("scope", "openid profile email");
        form.put("redirect_uri", redirectUri);
        form.put("code_challenge_method", "S256");
        form.put("code_challenge", "P8SQZ23DZjuc5u6IogwrU7ufXit9dbLZMxfGWtbzeeI");
        form.put("id_token", idToken);

        HttpResponse<String> response = postForm(parPath, form);
        assertThat(response.statusCode()).isEqualTo(201);

        String requestUri = readJsonString(response.body(), "request_uri");
        assertThat(requestUri).isNotBlank();
        return requestUri;
    }

    private static HttpResponse<String> postForm(String path, Map<String, String> form)
        throws IOException, InterruptedException
    {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl() + path))
                                         .timeout(Duration.ofSeconds(30))
                                         .header("Content-Type", "application/x-www-form-urlencoded")
                                         .POST(HttpRequest.BodyPublishers.ofString(asFormData(form)))
                                         .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String readJsonString(String payload, String fieldName)
    {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(payload);
        assertThat(matcher.find()).as("Missing field '%s' in payload: %s", fieldName, payload).isTrue();
        return matcher.group(1);
    }

    private static String asFormData(Map<String, String> form)
    {
        return form.entrySet()
                   .stream()
                   .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                   .reduce((left, right) -> left + "&" + right)
                   .orElse("");
    }

    private static String encode(String value)
    {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String baseUrl()
    {
        return KEYCLOAK.getAuthServerUrl();
    }
}
