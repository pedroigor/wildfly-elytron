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
package org.wildfly.security.http.util;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.cache.CachedIdentity;
import org.wildfly.security.auth.server.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.HttpServerRequest;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import java.io.IOException;
import java.util.Map;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.http.HttpConstants.SECURITY_IDENTITY;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SecurityIdentityServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory delegate;

    public SecurityIdentityServerMechanismFactory(HttpServerAuthenticationMechanismFactory delegate) {
        this.delegate = checkNotNullParam("delegate", delegate);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        return delegate.getMechanismNames(properties);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        SecurityIdentityCallbackHandler securityIdentityCallbackHandler = new SecurityIdentityCallbackHandler(callbackHandler);
        final HttpServerAuthenticationMechanism delegate = this.delegate.createAuthenticationMechanism(mechanismName, properties, securityIdentityCallbackHandler);
        if (delegate != null) {
            return new HttpServerAuthenticationMechanism() {

                @Override
                public String getMechanismName() {
                    return delegate.getMechanismName();
                }

                @Override
                public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
                    IdentityCache cache = delegate.getIdentityCache(request);

                    if (cache != null) {
                        CachedIdentity cachedIdentity = cache.lookup();

                        if (cachedIdentity != null) {
                            AuthorizeCallback authorizeCallback = new AuthorizeCallback(cachedIdentity.getName(), null);

                            try {
                                callbackHandler.handle(new Callback[]{authorizeCallback});
                            } catch (Exception e) {
                                throw new RuntimeException("Failed to retrieve identity from cache.", e);
                            }
                        }
                    }

                    delegate.evaluateRequest(request);

                    if (cache != null) {
                        SecurityIdentity identity = (SecurityIdentity) getNegotiatedProperty(SECURITY_IDENTITY);

                        if (identity != null) {
                            cache.store(identity.getPrincipal().getName(), identity);
                        }
                    }
                }

                @Override
                public Object getNegotiatedProperty(String propertyName) {
                    return SECURITY_IDENTITY.equals(propertyName) ? securityIdentityCallbackHandler.getSecurityIdentity()
                            : delegate.getNegotiatedProperty(propertyName);
                }

            };
        }
        return null;
    }

    private static class SecurityIdentityCallbackHandler implements CallbackHandler {

        private final CallbackHandler delegate;
        private SecurityIdentity securityIdentity;

        SecurityIdentityCallbackHandler(CallbackHandler delegate) {
            this.delegate = delegate;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            Callback[] theCallbacks = callbacks;
            SecurityIdentityCallback securityIdentityCallback = null;
            for (Callback current : callbacks) {
                if (current instanceof AuthenticationCompleteCallback
                        && ((AuthenticationCompleteCallback) current).succeeded()) {
                    theCallbacks = new Callback[callbacks.length + 1];
                    System.arraycopy(callbacks, 0, theCallbacks, 0, callbacks.length);
                    theCallbacks[theCallbacks.length - 1] = (securityIdentityCallback = new SecurityIdentityCallback());
                }
            }

            delegate.handle(theCallbacks);
            if (securityIdentityCallback != null) {
                securityIdentity = securityIdentityCallback.getSecurityIdentity();
            }
        }

        SecurityIdentity getSecurityIdentity() {
            return securityIdentity;
        }

    }

}
