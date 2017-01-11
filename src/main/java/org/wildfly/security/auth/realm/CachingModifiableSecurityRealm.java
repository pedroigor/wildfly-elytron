/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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

package org.wildfly.security.auth.realm;

import java.security.Principal;

import org.wildfly.security.auth.server.CloseableIterator;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.cache.RealmIdentityCache;

/**
 * <p>A wrapper class that provides caching capabilities for a {@link org.wildfly.security.auth.server.ModifiableSecurityRealm} and its identities.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class CachingModifiableSecurityRealm extends CachingSecurityRealm implements ModifiableSecurityRealm {

    /**
     * Creates a new instance.
     *
     * @param realm the {@link SecurityRealm} whose {@link RealmIdentity} should be cached..
     * @param cache the {@link RealmIdentityCache} instance
     */
    public CachingModifiableSecurityRealm(CacheableSecurityRealm realm, RealmIdentityCache cache) {
        super(realm, cache);
    }

    @Override
    public ModifiableRealmIdentity getRealmIdentityForUpdate(Principal principal) throws RealmUnavailableException {
        removeFromCache(principal);
        return getModifiableSecurityRealm().getRealmIdentityForUpdate(principal);
    }

    @Override
    public CloseableIterator<ModifiableRealmIdentity> getRealmIdentityIterator() throws RealmUnavailableException {
        removeAllFromCache();
        return getModifiableSecurityRealm().getRealmIdentityIterator();
    }

    private ModifiableSecurityRealm getModifiableSecurityRealm() {
        return (ModifiableSecurityRealm) getCacheableRealm();
    }
}
