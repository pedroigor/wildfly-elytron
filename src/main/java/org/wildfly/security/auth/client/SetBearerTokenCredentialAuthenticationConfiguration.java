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

package org.wildfly.security.auth.client;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.BearerTokenCredential;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class SetBearerTokenCredentialAuthenticationConfiguration extends AuthenticationConfiguration {

    private final BearerTokenCredential credential;

    SetBearerTokenCredentialAuthenticationConfiguration(final AuthenticationConfiguration parent, final BearerTokenCredential credential) {
        super(parent);
        this.credential = credential;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            CredentialCallback credentialCallback = (CredentialCallback) callback;
            if (credentialCallback.isCredentialTypeSupported(BearerTokenCredential.class)) {
                credentialCallback.setCredential(credential);
                return;
            }
        }
        super.handleCallback(callbacks, index);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetBearerTokenCredentialAuthenticationConfiguration(newParent, credential);
    }
}
