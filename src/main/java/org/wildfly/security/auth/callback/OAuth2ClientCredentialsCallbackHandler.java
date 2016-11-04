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

package org.wildfly.security.auth.callback;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.util.HttpClient.HttpHeader.authorizationBasic;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.SSLContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.net.URI;
import java.security.AccessController;
import java.security.GeneralSecurityException;

import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.util.HttpClient;
import org.wildfly.security.util.HttpClient.HttpRequest;

/**
 * <p>A {@link CallbackHandler} that is capable of obtaining a {@link BearerTokenCredential} using
 * the OAuth2 Client Credentials Grant Type.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class OAuth2ClientCredentialsCallbackHandler implements CallbackHandler {

    private final URI tokenEndpointUri;
    private final String clientId;
    private final String clientSecret;
    private final String scopes;

    /**
     * Creates a new instance.
     *
     * @param tokenEndpointUri the OAuth2 Token Endpoint {@link URI}
     * @param clientId         the client id
     * @param clientSecret     the client secret
     */
    public OAuth2ClientCredentialsCallbackHandler(URI tokenEndpointUri, String clientId, String clientSecret) {
        this(tokenEndpointUri, clientId, clientSecret, null);
    }

    /**
     * Creates a new instance.
     *
     * @param tokenEndpointUri the OAuth2 Token Endpoint {@link URI}
     * @param clientId         the client id
     * @param clientSecret     the client secret
     * @param scopes           a string with the scope of the access request
     */
    public OAuth2ClientCredentialsCallbackHandler(URI tokenEndpointUri, String clientId, String clientSecret, String scopes) {
        this.tokenEndpointUri = checkNotNullParam("tokenEndpointUri", tokenEndpointUri);
        this.clientId = checkNotNullParam("clientId", clientId);
        this.clientSecret = checkNotNullParam("clientSecret", clientSecret);
        this.scopes = scopes;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof CredentialCallback) {
                CredentialCallback credentialCallback = (CredentialCallback) callback;

                if (credentialCallback.isCredentialTypeSupported(BearerTokenCredential.class)) {
                    try {
                        HttpRequest request = HttpClient.builder().sslContext(resolveSSLContext()).build()
                                .post(tokenEndpointUri.toURL())
                                .header(authorizationBasic(clientId, clientSecret))
                                .param("grant_type", "client_credentials");

                        if (scopes != null) {
                            request.param("scope", scopes);
                        }

                        BearerTokenCredential credential = request
                                .execute((inputStream, throwable) -> {
                                    if (throwable != null) {
                                        throw log.httpClientUnexpectedResponseFromServer(throwable);
                                    }
                                    JsonObject jsonObject = Json.createReader(inputStream).readObject();
                                    String accessToken = jsonObject.getString("access_token");
                                    return new BearerTokenCredential(accessToken);
                                });

                        credentialCallback.setCredential(credential);
                    } catch (Exception cause) {
                        throw log.mechCallbackHandlerFailedForUnknownReason("OAuth2 Credentials Grant Type", cause);
                    }
                }
            }
        }
    }

    private SSLContext resolveSSLContext() throws GeneralSecurityException {
        if ("http".equals(tokenEndpointUri.getScheme())) {
            return null;
        }

        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);

        return contextConfigurationClient.getSSLContext(tokenEndpointUri, AuthenticationContext.captureCurrent());
    }
}
