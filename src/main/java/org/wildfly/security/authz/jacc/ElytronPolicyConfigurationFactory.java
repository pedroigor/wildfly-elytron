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
import org.wildfly.security.authz.jacc.action.GetContextIDAction;
import org.wildfly.security.manager.WildFlySecurityManager;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.authz.jacc.ElytronPolicyConfiguration.State.OPEN;

/**
 * <p>A {@link javax.security.jacc.PolicyConfigurationFactory} implementation.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronPolicyConfigurationFactory extends PolicyConfigurationFactory {

    /**
     * <p>Returns the {@link javax.security.jacc.PolicyConfiguration} associated with the current policy context identifier.</p>
     *
     * <p>This method only returns {@link javax.security.jacc.PolicyConfiguration} transitioned to the <i>in service</i> state.
     * If the configuration associated with the current policy context identifier is in a different state, a exception is thrown.</p>
     *
     * @return This method always returns a configuration instance transitioned with the <i>in service</i> state and associated
     *         with the current policy context identifier.
     * @throws PolicyContextException If the configuration is in a different state than <i>in service</i>, no policy context identifier
     * was set or if no configuration is found for the given identifier.
     */
    public static <P extends PolicyConfiguration> P getCurrentPolicyConfiguration() throws PolicyContextException {
        String contextID;

        if (WildFlySecurityManager.isChecking()) {
            contextID = doPrivileged(new GetContextIDAction());
        } else {
            contextID = PolicyContext.getContextID();
        }

        try {
            ElytronPolicyConfigurationFactory policyConfigurationFactory = (ElytronPolicyConfigurationFactory) PolicyConfigurationFactory.getPolicyConfigurationFactory();
            P policyConfiguration = (P) policyConfigurationFactory.getPolicyConfiguration(contextID);

            if (policyConfiguration == null) {
                throw log.authzInvalidPolicyContextIdentifier(contextID);
            }

            if (!policyConfiguration.inService()) {
                throw log.authzPolicyConfigurationNotInService(contextID);
            }

            return policyConfiguration;
        } catch (Exception e) {
            throw log.authzUnableToObtainPolicyConfiguration(contextID, e);
        }
    }

    private final PolicyConfigurationRegistry configurationRegistry = PolicyConfigurationRegistry.getInstance();

    public ElytronPolicyConfigurationFactory() {
        registerRoleMapperHandler();
    }

    @Override
    public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
        ElytronPolicyConfiguration policyConfiguration = getPolicyConfiguration(contextID);

        if (policyConfiguration == null) {
            return createPolicyConfiguration(contextID);
        }

        if (remove) {
            policyConfiguration.delete();
        }

        policyConfiguration.transitionTo(OPEN);

        return policyConfiguration;
    }

    @Override
    public boolean inService(String contextID) throws PolicyContextException {
        PolicyConfiguration policyConfiguration = getPolicyConfiguration(contextID);

        if (policyConfiguration == null) {
            return false;
        }

        return policyConfiguration.inService();
    }

    private void registerRoleMapperHandler() {
        try {
            PolicyContext.registerHandler(RoleMapper.POLICY_CONTEXT_HANDLER_ID, new RoleMapperHandler(), true);
        } catch (PolicyContextException e) {
            throw ElytronMessages.log.authzFailToRegisterRoleMapper(e);
        }
    }

    private ElytronPolicyConfiguration getPolicyConfiguration(String contextID) {
        return this.configurationRegistry.get(contextID);
    }

    private ElytronPolicyConfiguration createPolicyConfiguration(final String contextID) {
        ElytronPolicyConfiguration policyConfiguration = new ElytronPolicyConfiguration(contextID);

        this.configurationRegistry.put(contextID, policyConfiguration);

        return policyConfiguration;
    }
}
