/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl.oauth2;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.net.MalformedURLException;
import java.net.URI;
import java.security.AccessController;
import java.util.Arrays;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.util.CodePointIterator;


/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2SaslClientTest extends BaseTestCase {

    private MockWebServer server;

    @Before
    public void onBefore() throws Exception {
        System.setProperty("wildfly.config.url", getClass().getResource("wildfly-oauth2-test-config.xml").toExternalForm());
        server = new MockWebServer();

        server.setDispatcher(createTokenEndpoint());

        server.start(50831);
    }

    @After
    public void onAfter() throws Exception {
        if (server != null) {
            server.shutdown();
        }
    }

    @Test
    public void testWithResourceOwnerCredentialsUsingMatchUserInfo() throws Exception {
        URI serverUri = URI.create("protocol://test1.org");
        SaslClient saslClient = createSaslClientFromConfiguration(serverUri);

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        do {
            message = saslClient.evaluateChallenge(message);
            if (message == null) break;
            message = saslServer.evaluateResponse(message);
        } while (message != null);

        assertTrue(saslServer.isComplete());
        assertTrue(saslClient.isComplete());
    }

    @Test
    public void testWithClientCredentialsUsingConfiguration() throws Exception {
        URI serverUri = URI.create("protocol://test2.org");
        SaslClient saslClient = createSaslClientFromConfiguration(serverUri);

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        do {
            message = saslClient.evaluateChallenge(message);
            if (message == null) break;
            message = saslServer.evaluateResponse(message);
        } while (message != null);

        assertTrue(saslServer.isComplete());
        assertTrue(saslClient.isComplete());
    }

    @Test
    public void failedWithBearerTokenFromConfiguration() throws Exception {
        SaslClient saslClient = createSaslClientFromConfiguration(URI.create("protocol://test3.org"));

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        message = saslClient.evaluateChallenge(message);

        try {
            message = saslServer.evaluateResponse(message);
        } catch (SaslException e) {
            assertTrue(e.getCause() instanceof RealmUnavailableException);
            RealmUnavailableException cause = (RealmUnavailableException) e.getCause();
            assertTrue(cause.getMessage().contains("ELY01114"));
        }
    }

    @Test
    public void failedInvalidClientCredentialsUsingConfiguration() throws Exception {
        URI serverUri = URI.create("protocol://test4.org");
        SaslClient saslClient = createSaslClientFromConfiguration(serverUri);

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        try {
            do {
                message = saslClient.evaluateChallenge(message);
                if (message == null) break;
                message = saslServer.evaluateResponse(message);
            } while (message != null);
            fail("Expected bad response from server");
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(e.getCause().getMessage().contains("ELY03030"));
        }
    }

    @Test
    public void testWithResourceOwnerCredentials() throws Exception {
        URI serverUri = URI.create("protocol://test5.org");
        SaslClient saslClient = createSaslClientFromConfiguration(serverUri);

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        do {
            message = saslClient.evaluateChallenge(message);
            if (message == null) break;
            message = saslServer.evaluateResponse(message);
        } while (message != null);

        assertTrue(saslServer.isComplete());
        assertTrue(saslClient.isComplete());
    }

    @Test
    public void testWithBearerTokenFromConfiguration() throws Exception {
        SaslClient saslClient = createSaslClientFromConfiguration(URI.create("protocol://test5.org"));

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        do {
            message = saslClient.evaluateChallenge(message);
            if (message == null) break;
            message = saslServer.evaluateResponse(message);
        } while (message != null);

        assertTrue(saslServer.isComplete());
        assertTrue(saslClient.isComplete());
    }

    @Test
    public void failedResourceOwnerCredentialsUsingConfiguration() throws Exception {
        URI serverUri = URI.create("protocol://test6.org");
        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration authenticationConfiguration = contextConfigurationClient.getAuthenticationConfiguration(serverUri, context);
        SaslClient saslClient = contextConfigurationClient.createSaslClient(serverUri, authenticationConfiguration, Arrays.asList(SaslMechanismInformation.Names.OAUTHBEARER));

        assertNotNull("OAuth2SaslClient is null", saslClient);

        SaslServer saslServer = new SaslServerBuilder(OAuth2SaslServerFactory.class, SaslMechanismInformation.Names.OAUTHBEARER)
                .setServerName("resourceserver.comn")
                .setProtocol("imap")
                .addRealm("oauth-realm", createSecurityRealmMock())
                .setDefaultRealmName("oauth-realm")
                .build();

        byte[] message = AbstractSaslParticipant.NO_BYTES;

        try {
            do {
                message = saslClient.evaluateChallenge(message);
                if (message == null) break;
                message = saslServer.evaluateResponse(message);
            } while (message != null);
            fail("Expected bad response from server");
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(e.getCause().getMessage().contains("ELY03030"));
        }
    }

    private SecurityRealm createSecurityRealmMock() throws MalformedURLException {
        return TokenSecurityRealm.builder().validator(JwtValidator.builder().build()).principalClaimName("preferred_username").build();
    }

    private Dispatcher createTokenEndpoint() {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String body = recordedRequest.getBody().readUtf8();
                String authorizationHeader = recordedRequest.getHeader("Authorization");

                if (authorizationHeader == null) {
                    return new MockResponse().setResponseCode(401).addHeader("WWW-Authenticate", "Basic realm=realm\"test\"");
                }

                String clientIdAndSecret = CodePointIterator.ofString(authorizationHeader.substring("Basic".length() + 1)).base64Decode().asUtf8String().drainToString();

                boolean resourceOwnerCredentials = body.contains("grant_type=password");
                boolean clientCredentials = body.contains("grant_type=client_credentials");

                if (resourceOwnerCredentials
                        && clientIdAndSecret.equals("elytron-client:dont_tell_me")
                        && (body.contains("username=alice") || body.contains("username=jdoe"))
                        && body.contains("password=dont_tell_me")) {
                    JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

                    tokenBuilder.add("access_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiYXV0aC5zZXJ2ZXIiLCJhdWQiOiJmb3JfbWUiLCJleHAiOjE3NjA5OTE2MzUsInByZWZlcnJlZF91c2VybmFtZSI6Impkb2UifQ.SoPW41_mOFnKXdkwVG63agWQ2k09dEnEtTBztnxHN64");

                    return new MockResponse().setBody(tokenBuilder.build().toString());
                } else if (clientCredentials
                        && clientIdAndSecret.equals("elytron-client:dont_tell_me")) {
                    JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();

                    tokenBuilder.add("access_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiYXV0aC5zZXJ2ZXIiLCJhdWQiOiJmb3JfbWUiLCJleHAiOjE3NjA5OTE2MzUsInByZWZlcnJlZF91c2VybmFtZSI6Impkb2UifQ.SoPW41_mOFnKXdkwVG63agWQ2k09dEnEtTBztnxHN64");

                    return new MockResponse().setBody(tokenBuilder.build().toString());
                }

                return new MockResponse().setResponseCode(400);
            }
        };
    }

    private SaslClient createSaslClientFromConfiguration(URI serverUri) throws SaslException {
        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        AuthenticationConfiguration authenticationConfiguration = contextConfigurationClient.getAuthenticationConfiguration(serverUri, context);
        return contextConfigurationClient.createSaslClient(serverUri, authenticationConfiguration, Arrays.asList(SaslMechanismInformation.Names.OAUTHBEARER));
    }
}
