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
import java.util.Set;

/**
 * <p>A role mapper is responsible for principal-to-role mapping.<p>
 *
 * <p>Principal-to-role mapping is usually application or module scoped. That is, the same principal-to-role mappings
 * must apply in the access decisions applied at all of the modules (that may represent separate policy contexts) that
 * comprise an application or parent module.</p>
 *
 * <p>{@code RoleMapper} instances can be set on a per module basis by setting them on {@link org.wildfly.security.authz.jacc.ElytronPolicyConfiguration}
 * instances using its {@link org.wildfly.security.authz.jacc.ElytronPolicyConfiguration#setRoleMapper(RoleMapper)} method. If none is provided for
 * a particular policy configuration a default implementation is used.</p>
 *
 * <p>Instances are obtained from the {@link javax.security.jacc.PolicyContext} as follows:</p>
 *
 * <pre>
 *  RoleMapper roleMapper = (RoleMapper) PolicyContext.getContext(RoleMapper.POLICY_CONTEXT_HANDLER_ID);
 * </pre>
 *
 * <p>In this case, the instance returned is always the one associated with the current policy context identifier. See {@link javax.security.jacc.PolicyContext#getContextID()}.</p>
 *
 * <p>This interface provides convenient methods for any kind of role mapping such as:</p>
 *
 * <ul>
 *     <li>1:1 principal to role mapping, where a principal maps directly to a role.</li>
 *     <li>1:N principal to role mapping, where a principal (eg.: representing a group or an user identifier) maps to one or more roles.</li>
 * </ul>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 *
 * @see org.wildfly.security.authz.jacc.DefaultRoleMapper
 * @see org.wildfly.security.authz.jacc.RoleMapperHandler
 */
public interface RoleMapper {

    String POLICY_CONTEXT_HANDLER_ID = RoleMapper.class.getName();

    Set<String> getRoles(Principal[] principals);

}
