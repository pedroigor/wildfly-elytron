/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.Cookie;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.HttpServerSession;

import java.io.InputStream;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.InetSocketAddress;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wildfly.common.Assert.checkNotNullParam;

/**
 * A {@link HttpServerAuthenticationMechanism} with a stored {@link AccessControlContext} that is used for all request
 * processing calls.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class PrivilegedServerMechanism implements HttpServerAuthenticationMechanism {

    private final HttpServerAuthenticationMechanism mechanism;
    private final AccessControlContext accessControlContext;

    PrivilegedServerMechanism(final HttpServerAuthenticationMechanism mechanism, final AccessControlContext accessControlContext) {
        this.mechanism = checkNotNullParam("mechanism", mechanism);
        this.accessControlContext = checkNotNullParam("accessControlContext", accessControlContext);
    }

    @Override
    public String getMechanismName() {
        return mechanism.getMechanismName();
    }

    @Override
    public void evaluateRequest(final HttpServerRequest request) throws HttpAuthenticationException {
        try {
            AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                mechanism.evaluateRequest(new HttpServerRequestWrapper(request));
                return null;
            }, accessControlContext);
        } catch (PrivilegedActionException pae) {
            try {
                throw pae.getCause();
            } catch (HttpAuthenticationException | RuntimeException | Error e) {
                throw e;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
    }

    private HttpServerMechanismsResponder wrap(final HttpServerMechanismsResponder toWrap) {
        return toWrap != null ? (HttpServerResponse r) -> AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            toWrap.sendResponse(r);
            return null;
        }, accessControlContext) : null;
    }

    private class HttpServerRequestWrapper implements HttpServerRequest {

        private final HttpServerRequest wrapped;

        private HttpServerRequestWrapper(HttpServerRequest toWrap) {
            wrapped = toWrap;
        }

        @Override
        public List<String> getRequestHeaderValues(String headerName) {
            return wrapped.getRequestHeaderValues(headerName);
        }

        @Override
        public String getFirstRequestHeaderValue(String headerName) {
            return wrapped.getFirstRequestHeaderValue(headerName);
        }

        @Override
        public void noAuthenticationInProgress(HttpServerMechanismsResponder responder) {
            wrapped.noAuthenticationInProgress(wrap(responder));
        }

        @Override
        public void authenticationInProgress(HttpServerMechanismsResponder responder) {
            wrapped.authenticationInProgress(wrap(responder));
        }

        @Override
        public void authenticationComplete(SecurityIdentity securityIdentity, HttpServerMechanismsResponder responder) {
            wrapped.authenticationComplete(securityIdentity, wrap(responder));
        }

        @Override
        public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
            wrapped.authenticationFailed(message, wrap(responder));
        }

        @Override
        public void badRequest(HttpAuthenticationException failure, HttpServerMechanismsResponder responder) {
            wrapped.badRequest(failure, wrap(responder));
        }

        @Override
        public String getRequestMethod() {
            return wrapped.getRequestMethod();
        }

        @Override
        public String getRequestURI() {
            return wrapped.getRequestURI();
        }

        @Override
        public Map<String, String[]> getQueryParameters() {
            return wrapped.getQueryParameters();
        }

        @Override
        public Cookie[] getCookies() {
            return wrapped.getCookies();
        }

        @Override
        public InputStream getInputStream() {
            return wrapped.getInputStream();
        }

        @Override
        public InetSocketAddress getSourceAddress() {
            return wrapped.getSourceAddress();
        }

        @Override
        public HttpServerSession getSession(boolean create) {
            return wrapped.getSession(create);
        }

        @Override
        public HttpServerSession getSession(String id) {
            return wrapped.getSession(id);
        }

        @Override
        public Set<String> getSessions() {
            return wrapped.getSessions();
        }
    }

}
