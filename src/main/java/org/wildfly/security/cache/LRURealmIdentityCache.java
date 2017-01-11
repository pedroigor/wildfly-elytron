package org.wildfly.security.cache;

import static org.wildfly.common.Assert.checkMinimumParameter;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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
    private final Map<Principal, Set<Principal>> realmCache;

    public LRURealmIdentityCache(int maxEntries) {
        checkMinimumParameter("maxEntries", 1, maxEntries);
        cache = Collections.synchronizedMap(new LinkedHashMap<Principal, RealmIdentity>(16, DEFAULT_LOAD_FACTOR, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry eldest) {
                return cache.size()  > maxEntries;
            }
        });
        realmCache = Collections.synchronizedMap(new HashMap<Principal, Set<Principal>>(16));
    }

    @Override
    public void put(Principal key, RealmIdentity newValue) {
        RealmIdentity realmIdentity = cache.computeIfAbsent(key, principal -> {
            HashSet<Principal> principals = new HashSet<>();
            principals.add(key);
            realmCache.putIfAbsent(newValue.getRealmIdentityPrincipal(), principals);
            return newValue;
        });

        if (realmIdentity != null) {
            realmCache.get(realmIdentity.getRealmIdentityPrincipal()).add(key);
        }
    }

    @Override
    public RealmIdentity get(Principal key) {
        RealmIdentity cached = cache.get(key);

        if (cached != null) {
            return cached;
        }

        Set<Principal> domainPrincipal = realmCache.get(key);

        if (domainPrincipal != null) {
            return cache.get(domainPrincipal.iterator().next());
        }

        return null;
    }

    @Override
    public void remove(Principal key) {
        if (cache.containsKey(key)) {
            realmCache.remove(cache.remove(key).getRealmIdentityPrincipal()).forEach(principal -> cache.remove(principal));
        } else if (realmCache.containsKey(key)) {
            realmCache.remove(key).forEach(cache::remove);
        }
    }

    @Override
    public void clear() {
        cache.clear();
    }
}
