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

package org.wildfly.security.sasl.gssapi;

import static org.wildfly.security.sasl.gssapi.JaasUtil.loginClient;
import static org.wildfly.security.sasl.gssapi.JaasUtil.loginServer;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * Test a JDK supplied client can communicate with a WildFly server.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JdkClientWildFlyServerSuiteChild extends BaseGssapiTests {

    private static Subject clientSubject;
    private static Subject serverSubject;
    private static Subject unboundServerSubject;

    @BeforeClass
    public static void initialise() throws LoginException {
        clientSubject = loginClient();
        serverSubject = loginServer(GssapiTestSuite.serverKeyTab, false);
        unboundServerSubject = loginServer(GssapiTestSuite.serverKeyTab, true);
    }

    @AfterClass
    public static void destroy() {
        clientSubject = null;
        serverSubject = null;
    }

    @Override
    protected SaslClient getSaslClient(final boolean authServer, final VerificationMode mode) throws Exception {
        Map<String, String> props = Collections.emptyMap();

        SaslClient baseClient = createClient(clientSubject, false, authServer, mode, props);

        return new SubjectWrappingSaslClient(baseClient, clientSubject);
    }

    @Override
    protected SaslServer getSaslServer(final VerificationMode mode, final boolean unboundServer) throws Exception {
        Map<String, String> props = new HashMap<String, String>();
        props.put(WildFlySasl.RELAX_COMPLIANCE, Boolean.TRUE.toString());
        SaslServer baseServer = createServer(serverSubject, true, unboundServer, mode, props);

        return new SubjectWrappingSaslServer(baseServer, unboundServer ? unboundServerSubject : serverSubject);
    }

}
