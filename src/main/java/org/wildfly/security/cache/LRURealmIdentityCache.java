package org.wildfly.security.cache;

import static org.wildfly.common.Assert.checkMinimumParameter;

import java.security.Principal;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.wildfly.security.auth.server.RealmIdentity;

/**
 * A {@link RealmIdentityCache} implementation providing a LRU cache.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class LRURealmIdentityCache implements RealmIdentityCache {

    /**
     * The load factor. Th
     */
    private static final float DEFAULT_LOAD_FACTOR = 0.75f;

    /**
     * The cached entries
     */
    private final Map<Principal, RealmIdentity> cache;

    public LRURealmIdentityCache(int maxEntries) {
        checkMinimumParameter("maxEntries", 1, maxEntries);
        cache = Collections.synchronizedMap(new LinkedHashMap<Principal, RealmIdentity>(16, DEFAULT_LOAD_FACTOR, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry eldest) {
                return cache.size()  > maxEntries;
            }
        });
    }

    @Override
    public void put(Principal key, RealmIdentity newValue) {
        cache.computeIfAbsent(key, principal -> newValue);
    }

    @Override
    public RealmIdentity get(Principal key) {
        return cache.get(key);
    }

    @Override
    public void remove(Principal key) {
        cache.remove(key);
    }

    @Override
    public void clear() {
        cache.clear();
    }
}
