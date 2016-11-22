package org.wildfly.security.example;

import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JobRestartIdentityCacheTest {

    private SecurityDomain securityDomain;
    private Map<Integer, String> jobUserMapping = new HashMap<>();

    @Before
    public void onSetup() {
        Security.addProvider(new WildFlyElytronProvider());
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();

        Map<String, SimpleRealmEntry> users = new HashMap<>();

        addUser(users, "joe");
        addUser(users, "bob");

        realm.setPasswordMap(users);

        securityDomain = SecurityDomain.builder().addRealm("default", realm).build()
                .setDefaultRealmName("default")
                .setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.from(new LoginPermission()))
                .build();
    }

    @Test
    public void testRestoreJobWithIdentity() throws Exception {
        ExecutorService executor = Executors.newCachedThreadPool();

        createIdentity("joe").runAs(() -> {
            executor.submit(new JobWrapper(1, () -> System.out.println("Job 1 Executed by [" + securityDomain.getCurrentSecurityIdentity().getPrincipal() + "].")));
        });

        executor.submit(new JobWrapper(1, () -> System.out.println("Job 1 Executed [" + securityDomain.getCurrentSecurityIdentity().getPrincipal() + "].")));

        createIdentity("bob").runAs(() -> {
            executor.submit(new JobWrapper(2, () -> System.out.println("Job 2 Executed [" + securityDomain.getCurrentSecurityIdentity().getPrincipal() + "].")));
        });

        executor.submit(new JobWrapper(2, () -> System.out.println("Job 2 Executed [" + securityDomain.getCurrentSecurityIdentity().getPrincipal() + "].")));
        executor.submit(new JobWrapper(1, () -> System.out.println("Job 1 Executed [" + securityDomain.getCurrentSecurityIdentity().getPrincipal() + "].")));

        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.SECONDS);
    }

    private SecurityIdentity createIdentity(String name) throws RealmUnavailableException {
        ServerAuthenticationContext authenticationContext = securityDomain.createNewAuthenticationContext();
        authenticationContext.setAuthenticationName(name);
        authenticationContext.authorize();
        return authenticationContext.getAuthorizedIdentity();
    }

    private void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName) {
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
        securityRealm.put(userName, new SimpleRealmEntry(credentials, attributes));
    }

    final class JobWrapper implements Runnable {

        private final int id;
        private final SecurityIdentity currentIdentity;
        private Runnable runnable;

        public JobWrapper(int id, Runnable runnable) {
            this.id = id;
            this.runnable = runnable;
            currentIdentity = securityDomain.getCurrentSecurityIdentity();
        }

        @Override
        public void run() {
            SecurityIdentity identity = this.currentIdentity;

            if (identity.isAnonymous()) {
                ServerAuthenticationContext authenticationContext = securityDomain.createNewAuthenticationContext();

                try {
                    String userId = jobUserMapping.get(id);

                    if (userId != null) {
                        authenticationContext.setAuthenticationName(userId);
                        authenticationContext.authorize();
                        identity = authenticationContext.getAuthorizedIdentity();
                        System.out.println("Executing Job " + id + " restoring identity for user [" + identity.getPrincipal() + "] in Thread [" + Thread.currentThread().getName() + "].");
                    }
                } catch (RealmUnavailableException e) {
                    e.printStackTrace();
                }
            } else {
                jobUserMapping.put(id, identity.getPrincipal().getName());
                System.out.println("Storing user and executing Job " + id + " with runAs for user [" + identity.getPrincipal() + "] in Thread [" + Thread.currentThread().getName() + "].");
            }

            identity.runAs(runnable);
        }
    }
}
