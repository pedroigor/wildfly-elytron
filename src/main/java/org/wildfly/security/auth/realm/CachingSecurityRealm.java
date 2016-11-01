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

import static org.wildfly.common.Assert.checkNotNullParam;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * <p>A wrapper class that provides caching capabilities for a {@link org.wildfly.security.auth.server.SecurityRealm} and its identities.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class CachingSecurityRealm<R extends SecurityRealm> implements SecurityRealm {

    private final R realm;
    private final RealmIdentityCache cache;

    /**
     * Creates a new instance.
     *
     * @param realm the {@link SecurityRealm} whose {@link RealmIdentity} should be cached..
     * @param cache the {@link RealmIdentityCache} instance
     */
    public CachingSecurityRealm(R realm, RealmIdentityCache cache) {
        this.realm = checkNotNullParam("realm", realm);
        this.cache = checkNotNullParam("cache", cache);

        if (realm instanceof CacheableSecurityRealm) {
            CacheableSecurityRealm cacheable = (CacheableSecurityRealm) realm;
            cacheable.registerIdentityChangeListener(this::removeFromCache);
        } else {
            throw ElytronMessages.log.realmCacheUnexpectedType(realm, CacheableSecurityRealm.class);
        }
    }

    @Override
    public RealmIdentity getRealmIdentity(IdentityLocator locator) throws RealmUnavailableException {
        return cache.computeIfAbsent(locator, locator1 -> {
            try {
                return getRealm().getRealmIdentity(locator);
            } catch (RealmUnavailableException cause) {
                throw ElytronMessages.log.realmCacheFailedObtainIdentityFromCache(cause);
            }
        });
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
        return getRealm().getCredentialAcquireSupport(credentialType, algorithmName);
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return getRealm().getEvidenceVerifySupport(evidenceType, algorithmName);
    }

    @Override
    public void handleRealmEvent(RealmEvent event) {
        getRealm().handleRealmEvent(event);
    }

    /**
     * Removes a {@link RealmIdentity} referenced by the specified {@link IdentityLocator} from the cache.
     *
     * @param locator the {@link IdentityLocator} that references a previously cached realm identity
     */
    public void removeFromCache(IdentityLocator locator) {
        cache.remove(locator);
    }

    /**
     * Removes all cached identities from the cache.
     */
    public void removeAllFromCache() {
        cache.clear();
    }

    protected R getRealm() {
        return realm;
    }
}
