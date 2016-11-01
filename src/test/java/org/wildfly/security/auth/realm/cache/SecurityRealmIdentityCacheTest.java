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

package org.wildfly.security.auth.realm.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.spi.CachingProvider;
import java.io.NotSerializableException;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.infinispan.commons.CacheException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.realm.CachingSecurityRealm;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SecurityRealmIdentityCacheTest {

    private AtomicInteger realmHitCount = new AtomicInteger();

    @Before
    public void onBefore() {
        Security.addProvider(new WildFlyElytronProvider());
    }

    @After
    public void onAfter() {
        Caching.getCachingProvider().close();
    }

    @Test
    public void testRealmIdentitySimpleJavaMapCache() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(createRealmIdentitySimpleJavaMapCache())).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("joe", securityDomain);
            assertEquals(1, realmHitCount.get());
        }

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("bob", securityDomain);
            assertEquals(2, realmHitCount.get());
        }
    }

    @Test
    public void testRealmIdentityJCacheWithStoreByReference() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(createRealmIdentityJCache(false))).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("joe", securityDomain);
            assertEquals(1, realmHitCount.get());
        }

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("bob", securityDomain);
            assertEquals(2, realmHitCount.get());
        }
    }

    /**
     * Currently,  {@link IdentityLocator} is not serializable and can not be stored by a store-by-value cache.
     *
     * @throws Exception
     */
    @Test
    public void failRealmIdentityJCacheWithStoreByValue() throws Exception {
        try {
            SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(createRealmIdentityJCache(true))).build()
                    .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                    .build();

            assertAuthenticationAndAuthorization("joe", securityDomain);

            fail("Expected a failure due to usage of a store-by-value jcache");
        } catch (CacheException ce) {
            Throwable cause = ce.getCause();
            assertTrue(cause instanceof NotSerializableException);
        }
    }

    @Test
    public void testRealmIdentityNoCache() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(null)).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("joe", securityDomain);
        }

        assertEquals(10, realmHitCount.get());
    }

    private SecurityRealm createSecurityRealm(RealmIdentityCache cache) {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();

        addUser(users, "joe", "User");
        addUser(users, "bob", "User");

        realm.setPasswordMap(users);

        if (cache == null) {
            cache = new RealmIdentityCache() {
                @Override
                public void put(IdentityLocator locator, RealmIdentity realmIdentity) {

                }

                @Override
                public RealmIdentity get(IdentityLocator locator) {
                    return null;
                }

                @Override
                public void remove(IdentityLocator locator) {

                }

                @Override
                public void clear() {

                }
            };
        }

        return new CachingSecurityRealm<SecurityRealm>(new CacheableSecurityRealm() {
            @Override
            public void registerIdentityChangeListener(Consumer<IdentityLocator> listener) {

            }

            @Override
            public RealmIdentity getRealmIdentity(IdentityLocator locator) throws RealmUnavailableException {
                realmHitCount.incrementAndGet();
                return realm.getRealmIdentity(locator);
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
                return realm.getCredentialAcquireSupport(credentialType, algorithmName);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return getEvidenceVerifySupport(evidenceType, algorithmName);
            }
        }, cache) {
        };
    }

    private void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles) {
        List<Credential> credentials;
        try {
            credentials = Collections.singletonList(
                    new PasswordCredential(
                            PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                                    new ClearPasswordSpec("password".toCharArray()))));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));
        securityRealm.put(userName, new SimpleRealmEntry(credentials, attributes));
    }

    private void assertAuthenticationAndAuthorization(String username, SecurityDomain securityDomain) throws RealmUnavailableException {
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();

        sac.setAuthenticationName(username);
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("password".toCharArray())));
        assertTrue(sac.authorize(username));

        SecurityIdentity securityIdentity = sac.getAuthorizedIdentity();
        assertNotNull(securityIdentity);
        assertEquals(username, securityIdentity.getPrincipal().getName());
    }

    private RealmIdentityCache createRealmIdentitySimpleJavaMapCache() {
        return new RealmIdentityCache() {
            private Map<IdentityLocator, RealmIdentity> cache = new HashMap<>();
            @Override
            public void put(IdentityLocator locator, RealmIdentity realmIdentity) {
                cache.put(locator, realmIdentity);
            }

            @Override
            public RealmIdentity get(IdentityLocator locator) {
                return cache.get(locator);
            }

            @Override
            public void remove(IdentityLocator locator) {
                cache.remove(locator);
            }

            @Override
            public void clear() {
                cache.clear();
            }
        };
    }

    private RealmIdentityCache createRealmIdentityJCache(boolean storeByValue) {
        CachingProvider cachingProvider = Caching.getCachingProvider();
        CacheManager cacheManager = cachingProvider.getCacheManager();
        MutableConfiguration<IdentityLocator, RealmIdentity> configuration = new MutableConfiguration<>();

        configuration.setTypes(IdentityLocator.class, RealmIdentity.class);
        configuration.setStoreByValue(storeByValue);

        Cache<IdentityLocator, RealmIdentity> cache = cacheManager.createCache("realm-identity-cache", configuration);

        return new RealmIdentityCache() {
            @Override
            public void put(IdentityLocator locator, RealmIdentity realmIdentity) {
                cache.put(locator, realmIdentity);
            }

            @Override
            public RealmIdentity get(IdentityLocator locator) {
                return cache.get(locator);
            }

            @Override
            public void remove(IdentityLocator locator) {
                cache.remove(locator);
            }

            @Override
            public void clear() {
                cache.clear();
            }
        };
    }
}
