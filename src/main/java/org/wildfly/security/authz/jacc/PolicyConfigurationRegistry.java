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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <p>A simple registry with all {@link javax.security.jacc.PolicyConfiguration} created in runtime.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class PolicyConfigurationRegistry {

    private static final PolicyConfigurationRegistry instance = new PolicyConfigurationRegistry();

    private final Map<String, ElytronPolicyConfiguration> configuration = new ConcurrentHashMap<>();

    private PolicyConfigurationRegistry() {
    }

    static PolicyConfigurationRegistry getInstance() {
        return instance;
    }

    ElytronPolicyConfiguration get(String contextID) {
        return this.configuration.get(contextID);
    }

    void put(String contextID, ElytronPolicyConfiguration policyConfiguration) {
        this.configuration.put(contextID, policyConfiguration);
    }
}
