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

import org.wildfly.security.authz.jacc.action.GetPolicyAction;
import org.wildfly.security.manager.WildFlySecurityManager;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.WebResourcePermission;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security._private.ElytronMessages.log;

/**
 * <p>A {@link java.security.Policy} implementation that knows how to process JACC permissions.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronPolicyProvider extends Policy {

    private static final Policy instance = new ElytronPolicyProvider();

    private static final String ANY_AUTHENTICATED_USER_ROLE = "**";

    public static Policy getInstance() {
        return instance;
    }

    private final Policy delegate;

    private ElytronPolicyProvider() {
        if (WildFlySecurityManager.isChecking()) {
            this.delegate = doPrivileged(new GetPolicyAction());
        } else {
            this.delegate = Policy.getPolicy();
        }
    }

    @Override
    public boolean implies(ProtectionDomain domain, Permission permission) {
        if (supports(permission)) {
            try {
                ElytronPolicyConfiguration policyConfiguration = ElytronPolicyConfigurationFactory.getCurrentPolicyConfiguration();

                if (impliesExcludedPermission(permission, policyConfiguration)) {
                    return false;
                }

                if (impliesUncheckedPermission(permission, policyConfiguration)) {
                    return true;
                }

                return impliesRolePermission(domain, permission, policyConfiguration);
            } catch (PolicyContextException e) {
                log.authzFailedToCheckPermission(domain, permission, e);
                return false;
            }
        }

        return this.delegate.implies(domain, permission);
    }

    @Override
    public PermissionCollection getPermissions(ProtectionDomain domain) {
        return getPermissions(this.delegate.getPermissions(domain), domain.getPrincipals());
    }

    @Override
    public PermissionCollection getPermissions(CodeSource codeSource) {
        return getPermissions(this.delegate.getPermissions(codeSource), null);
    }

    @Override
    public void refresh() {
        //TODO: we can probably provide some caching for permissions and checks. In this case, we can use this method to refresh the cache.
    }

    private PermissionCollection getPermissions(PermissionCollection staticPermissions, Principal[] principals) {
        Permissions permissions = new Permissions();

        addPermissions(permissions, staticPermissions);

        try {
            ElytronPolicyConfiguration policyConfiguration = ElytronPolicyConfigurationFactory.getCurrentPolicyConfiguration();

            if (policyConfiguration != null) {
                addPermissions(permissions, policyConfiguration.getUncheckedPermissions());

                if (principals != null) {
                    for (String roleName : getRoleMapper().getRoles(principals)) {
                        Permissions rolePermissions = policyConfiguration.getRolePermissions().get(roleName);
                        addPermissions(permissions, rolePermissions);
                    }
                }
            }
        } catch (PolicyContextException e) {
            log.authzFailedGetDynamicPermissions(e);
        }

        return permissions;
    }

    private boolean impliesRolePermission(ProtectionDomain domain, Permission permission, ElytronPolicyConfiguration policyConfiguration) {
        Set<String> roles = getRoleMapper().getRoles(domain.getPrincipals());

        roles.add(ANY_AUTHENTICATED_USER_ROLE);

        Map<String, Permissions> rolePermissions = policyConfiguration.getRolePermissions();

        for (String roleName : roles) {
            Permissions permissions = rolePermissions.get(roleName);

            if (permissions != null) {
                if (permissions.implies(permission)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean impliesUncheckedPermission(Permission permission, ElytronPolicyConfiguration policyConfiguration) {
        Permissions uncheckedPermissions = policyConfiguration.getUncheckedPermissions();

        return uncheckedPermissions.implies(permission);
    }

    private boolean impliesExcludedPermission(Permission permission, ElytronPolicyConfiguration policyConfiguration) {
        Permissions excludedPermissions = policyConfiguration.getExcludedPermissions();

        return excludedPermissions.implies(permission);
    }

    private RoleMapper getRoleMapper() {
        RoleMapper roleMapper;

        try {
            roleMapper = (RoleMapper) PolicyContext.getContext(RoleMapper.POLICY_CONTEXT_HANDLER_ID);
        } catch (Exception e) {
            throw log.authzCouldNotObtainRoleMapper(e);
        }

        if (roleMapper == null) {
            throw log.authzRoleMapperNotRegistered();
        }

        return roleMapper;
    }

    private boolean supports(Permission permission) {
        return permission.getClass().getPackage().equals(WebResourcePermission.class.getPackage());
    }

    private void addPermissions(PermissionCollection newPermissions, PermissionCollection toAdd) {
        if (toAdd == null) {
            return;
        }

        Enumeration<Permission> enumeration = toAdd.elements();

        while (enumeration.hasMoreElements()) {
            newPermissions.add(enumeration.nextElement());
        }
    }
}
