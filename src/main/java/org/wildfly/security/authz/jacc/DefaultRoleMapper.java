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

import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * <p>Default {@link org.wildfly.security.authz.jacc.RoleMapper} implementation.</p>
 *
 * <p>The default implementations provides a very simple principal-to-role mapping, considering the following rules:</p>
 *
 * <ul>
 *     <li>Any {@link java.security.Principal} other than {@link java.security.acl.Group} is elected as a role representation.</li>
 *     <li>For any {@link java.security.acl.Group} principal, the members will be considered and roles extracted accordingly with the rule above.</li>
 * </ul>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class DefaultRoleMapper implements RoleMapper {

    @Override
    public Set<String> getRoles(Principal[] principals) {
        Set<String> roles = new HashSet<>();

        for (Principal principal : principals) {
            if (Group.class.isInstance(principal)) {
                Group group = (Group) principal;
                roles.addAll(extractGroupHierarchyNames(group));
            } else {
                roles.add(principal.getName());
            }
        }

        return roles;
    }

    private Set<String> extractGroupHierarchyNames(Group group) {
        Set<String> groupNames = new HashSet<>();

        if (group.members() == null) {
            return groupNames;
        }

        Enumeration<? extends Principal> members = group.members();

        while (members.hasMoreElements()) {
            Principal member = members.nextElement();

            if (Group.class.isInstance(member)) {
                groupNames.addAll(extractGroupHierarchyNames((Group) member));
            } else {
                groupNames.add(member.getName());
            }
        }

        return groupNames;
    }
}
