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

import org.hamcrest.core.IsInstanceOf;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.WebResourcePermission;
import java.security.Policy;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class LinkPolicyConfigurationTest extends AbstractAuthorizationTestCase {

    @Test
    public void testLinkPolicyConfigurationSharingRoleMapping() throws Exception {
        // let's create the parent module policy
        final WebResourcePermission parentPermission = new WebResourcePermission("/webResource", "PUT");
        String parentContextID = "parent-module";

        ElytronPolicyConfiguration parentPolicyConfiguration = createPolicyConfiguration(parentContextID, toConfigure -> {
                    toConfigure.addToRole("Administrator", parentPermission);
                    toConfigure.addToRole("User", parentPermission);
                }
        );

        Map<String, Set<String>> parentUserStore = new HashMap<>();
        HashSet<String> parentRoles = new HashSet<>();

        parentRoles.add("Administrator");

        parentUserStore.put("mary", parentRoles);

        // parent role mapper only supports user "mary" with role "Administrator"
        parentPolicyConfiguration.setRoleMapper(new StaticUserRoleMapper(parentUserStore));

        // let's create the first child module
        final WebResourcePermission child1Permission = new WebResourcePermission("/webResource", "POST");
        String child1ContextID = "child-module-1";

        ElytronPolicyConfiguration child1PolicyConfiguration = createPolicyConfiguration(child1ContextID, toConfigure -> {
                    toConfigure.addToRole("User", child1Permission);
                    toConfigure.addToRole("Manager", child1Permission);
                    toConfigure.addToRole("Administrator", child1Permission);
                }
        );

        Map<String, Set<String>> child1UserStore = new HashMap<>();
        HashSet<String> child1Roles = new HashSet<>();

        child1Roles.add("User");

        child1UserStore.put("john", child1Roles);

        // first child module role mapper only supports user "john" with role "User"
        child1PolicyConfiguration.setRoleMapper(new StaticUserRoleMapper(child1UserStore));

        // let's create the second child module
        final WebResourcePermission child2Permission = new WebResourcePermission("/webResource", "GET");
        String child2ContextID = "child-module-2";

        ElytronPolicyConfiguration child2PolicyConfiguration = createPolicyConfiguration(child2ContextID, toConfigure -> {
                    toConfigure.addToRole("Manager", child2Permission);
                    toConfigure.addToRole("User", child2Permission);
                }
        );

        Map<String, Set<String>> child2UserStore = new HashMap<>();
        HashSet<String> child2Roles = new HashSet<>();

        child2Roles.add("Manager");

        child2UserStore.put("smith", child2Roles);

        // second child role mapper only supports user "smith" with role "Manager"
        child2PolicyConfiguration.setRoleMapper(new StaticUserRoleMapper(child2UserStore));

        // link first child module with parent
        parentPolicyConfiguration.linkConfiguration(child1PolicyConfiguration);

        // link second child module with parent
        parentPolicyConfiguration.linkConfiguration(child2PolicyConfiguration);

        parentPolicyConfiguration.commit();
        child1PolicyConfiguration.commit();
        child2PolicyConfiguration.commit();

        // let's check now permissions for first child module
        PolicyContext.setContextID(child1ContextID);
        Policy policy = ElytronPolicyProvider.getInstance();

        // john is known by first child module, it should pass
        assertTrue(policy.implies(createProtectionDomain(createPrincipal("john")), child1Permission));

        // smith is not know by first module, but by second module. As they share the same role mapping, smith should be known by first module as well
        assertTrue(policy.implies(createProtectionDomain(createPrincipal("smith")), child1Permission));

        // same thing above, but using mary which is known only by parent module
        assertTrue(policy.implies(createProtectionDomain(createPrincipal("mary")), child1Permission));

        PolicyContext.setContextID(child2ContextID);

        // smith is known by first child module, it should pass
        assertTrue(policy.implies(createProtectionDomain(createPrincipal("smith")), child2Permission));

        // john is not know by first module, but by first module. As they share the same role mapping, john should be known by second module as well
        assertTrue(policy.implies(createProtectionDomain(createPrincipal("john")), child2Permission));

        // same thing above, but using mary which is known only by parent module. However, in this case we don't have a permission for mary/Administrator in the second module
        assertFalse(policy.implies(createProtectionDomain(createPrincipal("mary")), child2Permission));

        PolicyContext.setContextID(parentContextID);

        assertTrue(policy.implies(createProtectionDomain(createPrincipal("john")), parentPermission));
        assertFalse(policy.implies(createProtectionDomain(createPrincipal("smith")), parentPermission));

        parentPolicyConfiguration.delete();

        PolicyContext.setContextID(child1ContextID);

        // parent module was deleted, mary is longer resolvable
        assertFalse(policy.implies(createProtectionDomain(createPrincipal("mary")), child1Permission));
    }

    @Test
    public void testFailLinkSamePolicyConfiguration() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration parentPolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        try {
            parentPolicyConfiguration.linkConfiguration(parentPolicyConfiguration);
            fail("Should not be possible to link the same policy with itself");
        } catch (Exception e) {
            assertThat(e, new IsInstanceOf(IllegalArgumentException.class));
        }

        parentPolicyConfiguration.commit();
    }

    private Principal createPrincipal(final String name) {
        return new NamePrincipal(name);
    }

    public class StaticUserRoleMapper implements RoleMapper {

        private final Map<String, Set<String>> userStore;

        public StaticUserRoleMapper(Map<String, Set<String>> userStore) {
            this.userStore = userStore;
        }

        @Override
        public Set<String> getRoles(Principal[] principals) {
            for (Principal principal : principals) {
                Set<String> roles = this.userStore.get(principal.getName());

                if (roles != null) {
                    return roles;
                }
            }

            return Collections.emptySet();
        }
    }
}