package de.kunzit.keycloak.authentication.authenticators;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.testcontainers.images.ImagePullPolicy;
import org.testcontainers.images.PullPolicy;

import java.io.File;
import java.util.List;

class FullImageName {

    private static final String LATEST_VERSION   = "latest";
    private static final String NIGHTLY_VERSION  = "nightly";
    private static final String KEYCLOAK_VERSION = System.getProperty("keycloak.image.version",
                                                                      System.getProperty("keycloak.version", LATEST_VERSION));

    private static final boolean USE_JAR = Boolean.parseBoolean(System.getProperty("useJar", "false"));

    static String get()
    {
        String imageName = "keycloak";
        return "quay.io/keycloak/" + imageName + ":" + KEYCLOAK_VERSION;
    }

    static Boolean isNightlyVersion()
    {
        return NIGHTLY_VERSION.equalsIgnoreCase(KEYCLOAK_VERSION);
    }

    static Boolean isLatestVersion()
    {
        return LATEST_VERSION.equalsIgnoreCase(KEYCLOAK_VERSION);
    }

    static KeycloakContainer createContainer()
    {
        String fullImage = FullImageName.get();
        ImagePullPolicy pullPolicy = PullPolicy.defaultPolicy();
        if (isLatestVersion() || isNightlyVersion()) {
            pullPolicy = PullPolicy.alwaysPull();
        }
        KeycloakContainer keycloakContainer = new KeycloakContainer(fullImage)
            .withImagePullPolicy(pullPolicy);
        if (USE_JAR) {
            keycloakContainer = keycloakContainer.withProviderLibsFrom(List.of(new File("target/keycloak-token-auth.jar")));
        }
        else {
            keycloakContainer = keycloakContainer.withProviderClassesFrom("target/classes");
        }
        return keycloakContainer;
    }

}
