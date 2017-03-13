/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.impl;

import static org.wildfly.security.http.HttpConstants.BEARER_TOKEN;

import java.io.IOException;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class BearerTokenAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private final CallbackHandler callbackHandler;

    public BearerTokenAuthenticationMechanism(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    @Override
    public String getMechanismName() {
        return BEARER_TOKEN;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        List<String> authorizationValues = request.getRequestHeaderValues("Authorization");

        if (authorizationValues == null || authorizationValues.isEmpty()) {
            request.authenticationFailed("Bearer token required", response -> response.setStatusCode(403));
            return;
        } else if (authorizationValues.size() > 1) {
            request.authenticationFailed("Multiple Authorization headers found", response -> response.setStatusCode(400));
            return;
        }

        String authorizationValue = authorizationValues.get(0);

        if (!authorizationValue.startsWith("Bearer ")) {
            request.authenticationFailed("Authorization is not bearer", response -> response.setStatusCode(400));
            return;
        }

        String bearerToken = authorizationValue.substring("Bearer ".length());

        if ("".equals(bearerToken.trim())) {
            request.authenticationFailed("Invalid bearer token", response -> response.setStatusCode(403));
            return;
        }

        BearerTokenEvidence tokenEvidence = new BearerTokenEvidence(bearerToken);

        try {
            EvidenceVerifyCallback verifyCallback = new EvidenceVerifyCallback(tokenEvidence);

            callbackHandler.handle(new Callback[] {verifyCallback});

            if (verifyCallback.isVerified()) {
                AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, null);

                callbackHandler.handle(new Callback[] {authorizeCallback});

                if (authorizeCallback.isAuthorized()) {
                    callbackHandler.handle(new Callback[]{AuthenticationCompleteCallback.SUCCEEDED});
                    request.authenticationComplete();
                    return;
                }
            }

            request.authenticationFailed("Invalid bearer token");
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }
    }
}
