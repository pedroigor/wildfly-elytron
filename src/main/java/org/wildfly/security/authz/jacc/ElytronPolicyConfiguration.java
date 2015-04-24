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

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.authz.jacc.ElytronPolicyConfiguration.State.DELETED;
import static org.wildfly.security.authz.jacc.ElytronPolicyConfiguration.State.IN_SERVICE;
import static org.wildfly.security.authz.jacc.ElytronPolicyConfiguration.State.OPEN;

/**
 * <p>{@link javax.security.jacc.PolicyConfiguration} implementation.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 *
 * @see org.wildfly.security.authz.jacc.ElytronPolicyConfigurationFactory
 */
public class ElytronPolicyConfiguration implements PolicyConfiguration {

    /**
     * <p>An enum with all the possible states accordingly with the specification.</p>
     */
    public enum State {
        OPEN,
        IN_SERVICE,
        DELETED
    }

    private final String contextId;
    private State state = State.OPEN;
    private Permissions uncheckedPermissions = new Permissions();
    private Permissions excludedPermissions = new Permissions();
    private final Map<String, Permissions> rolePermissions = new ConcurrentHashMap<>();
    private Set<PolicyConfiguration> linkedPolicies = new LinkedHashSet<>();
    private RoleMapper roleMapper;

    ElytronPolicyConfiguration(String contextID) {
        this.contextId = contextID;
    }

    @Override
    public void addToExcludedPolicy(Permission permission) throws PolicyContextException {
        checkIfInOpenState();

        if (permission == null) {
            throw log.nullParameter("permission");
        }

        this.excludedPermissions.add(permission);
    }

    @Override
    public void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException {
        if (permissions == null) {
            throw log.nullParameter("permissions");
        }

        Enumeration<Permission> elements = permissions.elements();

        while (elements.hasMoreElements()) {
            addToExcludedPolicy(elements.nextElement());
        }
    }

    @Override
    public void addToRole(String roleName, Permission permission) throws PolicyContextException {
        checkIfInOpenState();

        if (permission == null) {
            throw log.nullParameter("permission");
        }

        if (!this.rolePermissions.containsKey(roleName)) {
            this.rolePermissions.put(roleName, new Permissions());
        }

        Permissions permissions = this.rolePermissions.get(roleName);

        permissions.add(permission);
    }

    @Override
    public void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException {
        if (permissions == null) {
            throw log.nullParameter("permissions");
        }

        Enumeration<Permission> elements = permissions.elements();

        while (elements.hasMoreElements()) {
            addToRole(roleName, elements.nextElement());
        }
    }

    @Override
    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException {
        checkIfInOpenState();

        if (permission == null) {
            throw log.nullParameter("permission");
        }

        this.uncheckedPermissions.add(permission);
    }

    @Override
    public void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException {
        if (permissions == null) {
            throw log.nullParameter("permissions");
        }

        Enumeration<Permission> elements = permissions.elements();

        while (elements.hasMoreElements()) {
            addToUncheckedPolicy(elements.nextElement());
        }
    }

    @Override
    public void commit() throws PolicyContextException {
        if (isDeleted()) {
            throw log.authzInvalidStateForOperation(this.state);
        }

        transitionTo(IN_SERVICE);
    }

    @Override
    public void delete() throws PolicyContextException {
        transitionTo(DELETED);
        this.uncheckedPermissions = new Permissions();
        this.excludedPermissions = new Permissions();
        this.rolePermissions.clear();
        this.linkedPolicies.remove(this);
        this.roleMapper = null;
    }

    @Override
    public String getContextID() throws PolicyContextException {
        return this.contextId;
    }

    @Override
    public boolean inService() {
        return IN_SERVICE.equals(this.state);
    }

    @Override
    public void linkConfiguration(PolicyConfiguration link) throws PolicyContextException {
        checkIfInOpenState();

        if (getContextID().equals(link.getContextID())) {
            throw log.authzLinkSamePolicyConfiguration(getContextID());
        }

        this.linkedPolicies.add(this);

        if (!this.linkedPolicies.add(link)) {
            return;
        }

        ElytronPolicyConfiguration linkedPolicyConfiguration = (ElytronPolicyConfiguration) link;

        linkedPolicyConfiguration.linkConfiguration(this);

        // policies share the same set of linked policies, so we can remove policies from the set when they are deleted.
        this.linkedPolicies = linkedPolicyConfiguration.getLinkedPolicies();
    }

    @Override
    public void removeExcludedPolicy() throws PolicyContextException {
        checkIfInOpenState();
        this.excludedPermissions = new Permissions();
    }

    @Override
    public void removeRole(String roleName) throws PolicyContextException {
        checkIfInOpenState();
        this.rolePermissions.remove(roleName);
    }

    @Override
    public void removeUncheckedPolicy() throws PolicyContextException {
        checkIfInOpenState();
        this.uncheckedPermissions = new Permissions();
    }

    /**
     * <p>Defines a {@link org.wildfly.security.authz.jacc.RoleMapper} for this configuration.</p>
     *
     * @param roleMapper The role mapper instance that must be associated with this configuration.
     */
    public void setRoleMapper(RoleMapper roleMapper) {
        this.roleMapper = roleMapper;
    }

    Set<PolicyConfiguration> getLinkedPolicies() {
        return this.linkedPolicies;
    }

    RoleMapper getRoleMapper() {
        return this.roleMapper;
    }

    Permissions getUncheckedPermissions() {
        return this.uncheckedPermissions;
    }

    Permissions getExcludedPermissions() {
        return this.excludedPermissions;
    }

    Map<String, Permissions> getRolePermissions() {
        return Collections.unmodifiableMap(this.rolePermissions);
    }

    void transitionTo(State state) {
        this.state = state;
    }

    private void checkIfInOpenState() {
        if (!OPEN.equals(this.state)) {
            throw log.authzInvalidStateForOperation(this.state);
        }
    }

    private boolean isDeleted() {
        return DELETED.equals(this.state);
    }
}
