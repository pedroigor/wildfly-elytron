/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.authz.jacc;

import org.junit.BeforeClass;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContextException;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class AbstractAuthorizationTestCase {

    @BeforeClass
    public static void onBeforeClass() {
        System.setProperty("javax.security.jacc.PolicyConfigurationFactory.provider", ElytronPolicyConfigurationFactory.class.getName());
        Policy.setPolicy(ElytronPolicyProvider.getInstance());
    }

    protected ElytronPolicyConfiguration createPolicyConfiguration(String contextID, ConfigurePoliciesAction configurationAction) throws ClassNotFoundException, PolicyContextException {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration(contextID, false);

        configurationAction.configure(policyConfiguration);

        return (ElytronPolicyConfiguration) policyConfiguration;
    }

    protected ProtectionDomain createProtectionDomain(Principal... principals) {
        return new ProtectionDomain(null, getClass().getProtectionDomain().getPermissions(), null, principals);
    }

    protected interface ConfigurePoliciesAction {

        void configure(PolicyConfiguration toConfigure) throws PolicyContextException;

    }
}
