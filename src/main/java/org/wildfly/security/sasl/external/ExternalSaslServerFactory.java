/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.external;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.sasl.WildFlySasl.EXTERNAL_AUTHENTICATION_METHOD;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.auth.callback.SSLCallback;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.util._private.Arrays2;

/**
 * Implementation of the SASL {@code EXTERNAL} server mechanism.  See <a href="https://tools.ietf.org/html/rfc4422#appendix-A">RFC 4422
 * appendix A</a> for more information about the {@code EXTERNAL} mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(SaslServerFactory.class)
public final class ExternalSaslServerFactory implements SaslServerFactory {

    private static Map<String, ExternalAuthentication> authenticationMethods = new HashMap<>();

    static {
        authenticationMethods.put(EXTERNAL_AUTHENTICATION_METHOD + ".tls", createTLSAuthenticationMethod());
    }

    private static ExternalAuthentication createTLSAuthenticationMethod() {
        return (authorizationId, cbh, props) -> {
            try {
                SSLSession sslSession = SSLSession.class.cast(props.get(SSLSession.class.getName()));

                if (sslSession != null) {
                    cbh.handle(new Callback[]{new SSLCallback(sslSession)});
                }
            } catch (SaslException e) {
                throw e;
            } catch (IOException e) {
                throw log.mechAuthorizationFailed(SaslMechanismInformation.Names.EXTERNAL, e).toSaslException();
            } catch (UnsupportedCallbackException e) {
                throw log.mechAuthorizationFailed(SaslMechanismInformation.Names.EXTERNAL, e).toSaslException();
            }
        };
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        String authenticationMethod = props != null ? String.class.cast(props.get(EXTERNAL_AUTHENTICATION_METHOD)) : null;

        if (authenticationMethod == null) {
            authenticationMethod = EXTERNAL_AUTHENTICATION_METHOD + ".tls";
        }

        ExternalAuthentication authentication = authenticationMethods.get(authenticationMethod);

        if (authentication == null) {
            throw new SaslException("Unknown external authentication method [" + authenticationMethod + "]");
        }

        return mechanism.equals(SaslMechanismInformation.Names.EXTERNAL) && getMechanismNames(props, false).length != 0 ? new ExternalSaslServer(cbh, props, authentication) : null;
    }

    private String[] getMechanismNames(final Map<String, ?> props, boolean query) {
        if (props == null) {
            return Arrays2.of(SaslMechanismInformation.Names.EXTERNAL);
        }
        if ("true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL)) && query) {
            return Arrays2.of(SaslMechanismInformation.Names.EXTERNAL);
        }
        if ("true".equals(props.get(Sasl.POLICY_FORWARD_SECRECY))
                || "true".equals(props.get(Sasl.POLICY_PASS_CREDENTIALS))
                || "true".equals(props.get(Sasl.POLICY_NOANONYMOUS))) {
            return WildFlySasl.NO_NAMES;
        }
        return Arrays2.of(SaslMechanismInformation.Names.EXTERNAL);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        return getMechanismNames(props, true);
    }

    interface ExternalAuthentication {

        void perform(String authorizationId, CallbackHandler cbh, Map<String, ?> props) throws SaslException;

    }
}
