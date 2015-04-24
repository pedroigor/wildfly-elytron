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

import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import sun.security.acl.GroupImpl;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.WebResourcePermission;
import java.security.Policy;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEnforcementTest extends AbstractAuthorizationTestCase {

    @Test
    public void testUncheckedPolicy() throws Exception {
        String contextID = "third-party-app";
        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> toConfigure.addToUncheckedPolicy(new WebResourcePermission("/webResource", "GET")));

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = ElytronPolicyProvider.getInstance();

        assertTrue(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "GET")));
        assertFalse(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "HEAD")));

        policyConfiguration.delete();
    }

    @Test
    public void testExcludedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
                    toConfigure.addToUncheckedPolicy(new WebResourcePermission("/webResource", "GET,PUT"));
                    toConfigure.addToExcludedPolicy(new WebResourcePermission("/webResource", "PUT"));
            }
        );

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = ElytronPolicyProvider.getInstance();

        // excluded policies have precedence over any other
        assertFalse(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "PUT")));

        policyConfiguration.delete();
    }

    @Test
    public void testRoleBasedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
            toConfigure.addToRole("Administrator", new WebResourcePermission("/webResource", "POST"));
        });

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = ElytronPolicyProvider.getInstance();

        assertTrue(policy.implies(createProtectionDomain(new NamePrincipal("Administrator")), new WebResourcePermission("/webResource", "POST")));
        assertFalse(policy.implies(createProtectionDomain(new NamePrincipal("Manager")), new WebResourcePermission("/webResource", "OPTIONS")));

        policyConfiguration.delete();
    }

    @Test
    public void testGroupRoleBasedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
            toConfigure.addToRole("Operator", new WebResourcePermission("/webResource", "POST"));
        });

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = ElytronPolicyProvider.getInstance();

        GroupImpl administrators = new GroupImpl("Administrators");

        administrators.addMember(new NamePrincipal("Operator"));

        assertTrue(policy.implies(createProtectionDomain(administrators), new WebResourcePermission("/webResource", "POST")));

        policyConfiguration.delete();
    }
}
