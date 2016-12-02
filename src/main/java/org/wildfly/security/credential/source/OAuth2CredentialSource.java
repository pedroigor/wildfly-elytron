package org.wildfly.security.credential.source;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * A {@link CredentialSource} capable of authenticating against a OAuth2 compliant authorization server and obtaining
 * access tokens in form of a {@link BearerTokenCredential}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2CredentialSource implements CredentialSource {

    /**
     * Creates a new {@link Builder} instance in order to configure and build a {@link OAuth2CredentialSource}.
     *
     * @param tokenEndpointUri the token endpoint that will be used to obtain OAuth2 access tokens
     * @return a new builder instance
     */
    public static Builder builder(URI tokenEndpointUri) {
        return new Builder(tokenEndpointUri);
    }

    private final String grantType;
    private final URI tokenEndpointUri;
    private final Consumer<Map<String, String>> consumer;
    private String scopes;

    /**
     * Creates a new instance.
     *
     * @param grantType the OAuth2 grant type as defined by the specification
     * @param tokenEndpointUri the OAuth2 Token Endpoint {@link URI}
     * @param scopes a string with the scope of the access request
     */
    private OAuth2CredentialSource(String grantType, URI tokenEndpointUri, String scopes) {
        this(grantType, tokenEndpointUri, (Consumer<Map<String, String>>) stringStringMap -> {}, scopes);
    }

    /**
     * Creates a new instance.
     *
     * @param grantType the OAuth2 grant type as defined by the specification
     * @param tokenEndpointUri the OAuth2 Token Endpoint {@link URI}
     * @param consumer a callback that can be used to push addition parameters to requests sent to the authorization server
     * @param scopes a string with the scope of the access request
     */
    private OAuth2CredentialSource(String grantType, URI tokenEndpointUri, Consumer<Map<String, String>> consumer, String scopes) {
        this.grantType = checkNotNullParam("grantType", grantType);
        this.tokenEndpointUri = checkNotNullParam("tokenEndpointUri", tokenEndpointUri);
        this.consumer = consumer;
        this.scopes = scopes;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
        return getCredential(credentialType, algorithmName, parameterSpec) != null ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
        if (BearerTokenCredential.class.equals(credentialType)) {
            try {
                HttpURLConnection connection = null;

                try {
                    connection = openConnection();
                    connection.setDoOutput(true);
                    connection.setRequestMethod("POST");
                    connection.setInstanceFollowRedirects(false);

                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                    HashMap<String, String> parameters = new HashMap<>();

                    parameters.put("grant_type", grantType);
                    consumer.accept(parameters);

                    if (scopes != null) {
                        parameters.put("scope", scopes);
                    }

                    byte[] paramBytes = buildParameters(parameters);

                    try (OutputStream outputStream = connection.getOutputStream()) {
                        outputStream.write(paramBytes);
                    }

                    try (InputStream inputStream = new BufferedInputStream(connection.getInputStream())) {
                        JsonObject jsonObject = Json.createReader(inputStream).readObject();
                        String accessToken = jsonObject.getString("access_token");
                        return credentialType.cast(new BearerTokenCredential(accessToken));
                    }
                } catch (IOException ioe) {
                    InputStream errorStream = null;

                    if (connection != null && connection.getErrorStream() != null) {
                        errorStream = connection.getErrorStream();

                        try (BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream))) {
                            StringBuffer response = reader.lines().reduce(new StringBuffer(), StringBuffer::append, (buffer1, buffer2) -> buffer1);
                            log.errorf(ioe, "Unexpected response from server [%s]. Response: [%s]", tokenEndpointUri, response);
                        } catch (IOException e) {
                            throw log.httpClientUnexpectedResponseFromServer(e);
                        }
                    }

                    throw log.httpClientUnexpectedResponseFromServer(ioe);
                } catch (Exception e) {
                    throw log.httpClientUnexpectedResponseFromServer(e);
                }
            } catch (Exception cause) {
                throw log.mechCallbackHandlerFailedForUnknownReason("OAuth2 Credentials Grant Type", cause);
            }
        }

        return null;
    }

    private SSLContext resolveSSLContext() throws GeneralSecurityException {
        if ("http".equals(tokenEndpointUri.getScheme())) {
            return null;
        }

        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);

        return contextConfigurationClient.getSSLContext(tokenEndpointUri, AuthenticationContext.captureCurrent());
    }

    private HttpURLConnection openConnection() throws IOException, GeneralSecurityException {
        try {
            log.debugf("Opening connection to server [%s]", tokenEndpointUri);
            SSLContext sslContext = resolveSSLContext();
            HttpURLConnection connection = (HttpURLConnection) tokenEndpointUri.toURL().openConnection();

            if (sslContext != null) {
                HttpsURLConnection https = (HttpsURLConnection) connection;

                https.setSSLSocketFactory(sslContext.getSocketFactory());
            }

            return connection;
        } catch (IOException cause) {
            throw cause;
        } catch (GeneralSecurityException e) {
            throw e;
        }
    }

    private byte[] buildParameters(Map<String, String> parameters) {
        ByteStringBuilder params = new ByteStringBuilder();

        parameters.entrySet().stream().forEach(entry -> {
            if (params.length() > 0) {
                params.append('&');
            }
            params.append(entry.getKey()).append('=').append(entry.getValue());
        });

        return params.toArray();
    }

    public static class Builder {

        private final URI tokenEndpointUri;
        private OAuth2CredentialSource grantType;
        private String scopes;

        Builder(URI tokenEndpointUri) {
            this.tokenEndpointUri = checkNotNullParam("tokenEndpointUri", tokenEndpointUri);
            this.grantType = new OAuth2CredentialSource("client_credentials", tokenEndpointUri, scopes);
        }

        /**
         * The scopes to grant access.
         *
         * @param scopes the scopes to grant access.
         * @return this instance
         */
        public Builder grantScopes(String scopes) {
            this.scopes = checkNotNullParam("scopes", scopes);
            return this;
        }

        /**
         * <p>Configure OAuth2 Resource Owner Password Grant Type as defined by the OAuth2 specification. When using this grant type,
         * make sure you have also configured one of the supported client authentication methods. For instance, by calling {@link #useClientCredentials(String, String)}.
         *
         * <p>Both username and password are going are obtained from the client configuration.
         *
         * @param resourceServerUri the URI of the resource server
         * @return this instance.
         */
        public Builder useResourceOwnerPassword(URI resourceServerUri) {
            grantType = new OAuth2CredentialSource("password", tokenEndpointUri, parameters -> {
                AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
                AuthenticationConfiguration authenticationConfiguration = contextConfigurationClient.getAuthenticationConfiguration(resourceServerUri, AuthenticationContext.captureCurrent());
                CallbackHandler callbackHandler = contextConfigurationClient.getCallbackHandler(authenticationConfiguration);
                NameCallback nameCallback = new NameCallback("Username:");
                PasswordCallback passwordCallback = new PasswordCallback("Password:", false);

                try {
                    callbackHandler.handle(new Callback[] {nameCallback, passwordCallback});
                } catch (Exception cause) {
                    throw log.couldNotObtainCredentialWithCause(cause);
                }

                String name = checkNotNullParam("Username", nameCallback.getName());
                char[] password = checkNotNullParam("Password", passwordCallback.getPassword());

                parameters.put("username", name);
                parameters.put("password", String.valueOf(password));
            }, scopes);
            return this;
        }

        /**
         * Creates a new {@link OAuth2CredentialSource} instance.
         *
         * @return a OAuth2 credential source
         */
        public OAuth2CredentialSource build() {
            return checkNotNullParam("grantType", grantType);
        }
    }
}
