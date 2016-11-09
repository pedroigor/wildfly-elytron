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
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

import org.wildfly.security.auth.callback.AuthenticationConfigurationCallback;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class SetConfigurationCallbackConfiguration extends AuthenticationConfiguration {

    private final CallbackHandler callbackHandler;

    SetConfigurationCallbackConfiguration(final AuthenticationConfiguration parent, final CallbackHandler callbackHandler) {
        super(parent);
        this.callbackHandler = callbackHandler;
    }

    void handleCallbacks(final AuthenticationConfiguration config, final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks.length > 0) {
            if (callbacks[0] instanceof AuthenticationConfigurationCallback) {
                return;
            }
        }
        Callback[] callbacksWithConfig = new Callback[callbacks.length + 1];
        System.arraycopy(callbacks, 0, callbacksWithConfig, 1, callbacks.length);
        callbacksWithConfig[0] = new AuthenticationConfigurationCallback(config);
        callbackHandler.handle(callbacksWithConfig);
        super.handleCallbacks(config, callbacks);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetConfigurationCallbackConfiguration(newParent, callbackHandler);
    }
}
