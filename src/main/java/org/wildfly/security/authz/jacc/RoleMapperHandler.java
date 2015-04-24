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

import org.wildfly.security._private.ElytronMessages;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * <p>A {@link javax.security.jacc.PolicyContextHandler} responsible for producing {@link org.wildfly.security.authz.jacc.RoleMapper}
 * accordingly with the current and active policy context identifier.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class RoleMapperHandler implements PolicyContextHandler {

    private final RoleMapper defaultMapper = new DefaultRoleMapper();

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        if (RoleMapper.POLICY_CONTEXT_HANDLER_ID.equals(key)) {
            String contextID = PolicyContext.getContextID();

            if (contextID == null) {
                throw ElytronMessages.log.authzContextIdentifierNotSet();
            }

            final ElytronPolicyConfiguration policyConfiguration = ElytronPolicyConfigurationFactory.getCurrentPolicyConfiguration();

            // here we create a wrapper in order to process linked policies and share the same principal-to-role-mapping
            // we can probably cache roles on a per contextID basis
            return new RoleMapper() {

                @Override
                public Set<String> getRoles(Principal[] principals) {
                    Set<String> roles = new HashSet<>();
                    Set<PolicyConfiguration> linkedPolicies = new HashSet<>(policyConfiguration.getLinkedPolicies());

                    linkedPolicies.add(policyConfiguration);

                    for (PolicyConfiguration linkedPolicy : linkedPolicies) {
                        ElytronPolicyConfiguration elytronPolicyConfiguration = (ElytronPolicyConfiguration) linkedPolicy;
                        RoleMapper roleMapper = elytronPolicyConfiguration.getRoleMapper();

                        if (roleMapper == null) {
                            roleMapper = defaultMapper;
                        }

                        if (roleMapper != null) {
                            roles.addAll(roleMapper.getRoles(principals));
                        }
                    }

                    return roles;
                }
            };
        }

        return null;
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return new String[] {RoleMapper.POLICY_CONTEXT_HANDLER_ID};
    }

    @Override
    public boolean supports(String key) throws PolicyContextException {
        return RoleMapper.POLICY_CONTEXT_HANDLER_ID.equals(key);
    }
}
