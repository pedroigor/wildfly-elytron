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
import org.hamcrest.core.IsSame;
import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.authz.jacc.action.GetPolicyAction;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.WebResourcePermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.util.List;

import static java.security.AccessController.doPrivileged;
import static java.util.Collections.list;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyConfigurationTest extends AbstractAuthorizationTestCase {

    @Test
    public void testCreateElytronPolicyConfigurationFactory() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

        Assert.assertThat(policyConfigurationFactory, new IsInstanceOf(ElytronPolicyConfigurationFactory.class));
    }

    @Test
    public void testCreateAndInstallDelegatingPolicy() throws Exception {
        Policy policy = ElytronPolicyProvider.getInstance();

        assertThat(policy, new IsSame<>(doPrivileged(new GetPolicyAction())));

        Policy mustBeTheSame = ElytronPolicyProvider.getInstance();

        assertThat(mustBeTheSame, new IsSame<>(doPrivileged(new GetPolicyAction())));
    }

    @Test
    public void testCreatePolicyConfiguration() throws Exception {
        final WebResourcePermission dynamicPermission1 = new WebResourcePermission("/webResource", "GET,PUT");
        final WebResourcePermission dynamicPermission2 = new WebResourcePermission("/webResource", "PUT");
        final WebResourcePermission dynamicPermission3 = new WebResourcePermission("/webResource", "HEAD");
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
                    toConfigure.addToUncheckedPolicy(dynamicPermission1);
                    toConfigure.addToRole("Administrator", dynamicPermission2);
                    toConfigure.addToExcludedPolicy(dynamicPermission3);
                }
        );

        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

        // must be in open state
        assertFalse(policyConfigurationFactory.inService(contextID));
        assertFalse(policyConfiguration.inService());

        // we now set the context id
        PolicyContext.setContextID(contextID);

        Policy policy = doPrivileged(new GetPolicyAction());

        PermissionCollection permissions = policy.getPermissions(createProtectionDomain(new NamePrincipal("Administrator")));
        List<Permission> staticPermissions = list(getClass().getProtectionDomain().getPermissions().elements());

        // policy configuration is not in service, thus only static permissions are returned
        assertEquals(staticPermissions.size(), list(permissions.elements()).size());

        policyConfiguration.commit();

        assertTrue(policyConfiguration.inService());
        assertTrue(policyConfigurationFactory.inService(contextID));

        permissions = policy.getPermissions(createProtectionDomain(new NamePrincipal("Administrator")));

        // now that policy configuration is in service, we must get static + dynamic permissions
        assertEquals(staticPermissions.size() + 2, list(permissions.elements()).size());

        assertTrue(permissions.implies(dynamicPermission1));
        assertTrue(permissions.implies(dynamicPermission2));

        // excluded permissions are never returned
        assertFalse(permissions.implies(dynamicPermission3));

        policyConfiguration.delete();
    }

    @Test
    public void testRemovePolicyConfiguration() throws Exception {
        final WebResourcePermission dynamicPermission1 = new WebResourcePermission("/webResource", "GET,PUT");
        final WebResourcePermission dynamicPermission2 = new WebResourcePermission("/webResource", "PUT");
        final WebResourcePermission dynamicPermission3 = new WebResourcePermission("/webResource", "HEAD");
        String contextID = "third-party-app";
        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
                    toConfigure.addToUncheckedPolicy(dynamicPermission1);
                    toConfigure.addToRole("Administrator", dynamicPermission2);
                    toConfigure.addToExcludedPolicy(dynamicPermission3);
                }
        );

        assertFalse(policyConfiguration.inService());

        policyConfiguration.commit();

        assertTrue(policyConfiguration.inService());

        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

        PolicyConfiguration removedPolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration(contextID, true);

        assertFalse(policyConfiguration.inService());
        assertThat(policyConfiguration, new IsSame<>(removedPolicyConfiguration));

        Policy policy = doPrivileged(new GetPolicyAction());

        PolicyContext.setContextID(contextID);

        PermissionCollection permissions = policy.getPermissions(createProtectionDomain(new NamePrincipal("Administrator")));
        List<Permission> staticPermissions = list(getClass().getProtectionDomain().getPermissions().elements());

        // policy configuration is deleted, dynamic permissions were cleared and only static permissions are returned
        assertEquals(staticPermissions.size(), list(permissions.elements()).size());

        assertFalse(permissions.implies(dynamicPermission1));
        assertFalse(permissions.implies(dynamicPermission2));
        assertFalse(permissions.implies(dynamicPermission3));
    }

    @Test
    public void testInServiceToOpenState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        PolicyConfiguration openPolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        assertThat(policyConfiguration, new IsSame<>(openPolicyConfiguration));

        assertFalse(openPolicyConfiguration.inService());

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        openPolicyConfiguration.addToUncheckedPolicy(dynamicPermission);
    }

    @Test
    public void testDeletedToOpenState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        PolicyConfiguration openPolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", true);

        assertThat(policyConfiguration, new IsSame<>(openPolicyConfiguration));

        assertFalse(openPolicyConfiguration.inService());

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        openPolicyConfiguration.addToUncheckedPolicy(dynamicPermission);
    }

    @Test
    public void testFailToAddUncheckedPermissionInServiceState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToUncheckedPolicy(dynamicPermission);
            fail("Permissions can not be added when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddExcludedPermissionInServiceState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToExcludedPolicy(dynamicPermission);
            fail("Permissions can not be added when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddRolePermissionInServiceState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToRole("Administrator", dynamicPermission);
            fail("Permissions can not be added when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveUncheckedPermissionInServiceState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        try {
            policyConfiguration.removeUncheckedPolicy();
            fail("Permissions can not be removed when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveExcludedPermissionInServiceState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        try {
            policyConfiguration.removeExcludedPolicy();
            fail("Permissions can not be removed when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveRolePermissionInServiceState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        try {
            policyConfiguration.removeRole("Administrator");
            fail("Permissions can not be removed when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToLinkInServiceState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.commit();

        try {
            PolicyConfiguration linkedPolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-pary-app/ejb", false);

            policyConfiguration.linkConfiguration(linkedPolicyConfiguration);

            fail("Links can not be added when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddUncheckedPermissionInDeletedState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.delete();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToUncheckedPolicy(dynamicPermission);
            fail("Permissions can not be added when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddExcludedPermissionInDeletedState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.delete();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToExcludedPolicy(dynamicPermission);
            fail("Permissions can not be added when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddRolePermissionInDeletedState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.delete();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToRole("Administrator", dynamicPermission);
            fail("Permissions can not be added when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveUncheckedPermissionInDeletedState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.delete();

        try {
            policyConfiguration.removeUncheckedPolicy();
            fail("Permissions can not be removed when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveExcludedPermissionInDeletedState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.delete();

        try {
            policyConfiguration.removeExcludedPolicy();
            fail("Permissions can not be removed when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveRolePermissionInDeletedState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.delete();

        try {
            policyConfiguration.removeRole("Administrator");
            fail("Permissions can not be removed when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToLinkInDeletedState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.delete();

        try {
            PolicyConfiguration linkedPolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-pary-app/ejb", false);

            policyConfiguration.linkConfiguration(linkedPolicyConfiguration);

            fail("Links can not be added when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToCommitDeletedState() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();
        PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration("third-party-app", false);

        policyConfiguration.delete();

        try {
            policyConfiguration.commit();
            fail("Commit can not be called when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }
}