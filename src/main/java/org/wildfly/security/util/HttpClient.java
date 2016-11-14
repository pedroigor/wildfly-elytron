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

package org.wildfly.security.util;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.util.HttpClient.HttpRequest.METHOD_POST;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * A simple HTTP Client utility class
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class HttpClient {

    public static Builder builder() {
        return new Builder();
    }

    private final Builder builder;

    private HttpClient(Builder builder) {
        this.builder = builder;
    }

    /**
     * Creates a {@link HttpRequest} instance that can be used to configure and send HTTP POST requests to the specified server <code>url</code>.
     *
     * @param url the server {@link URL} (must not be {@code null})
     * @return a {@link HttpRequest}
     */
    public HttpRequest post(URL url) {
        return new HttpRequest(METHOD_POST, url, builder);
    }

    public static final class Builder {

        private SSLContext sslContext;
        private HostnameVerifier hostNameVerifier;

        /**
         * Sets a {@link SSLContext} for HTTPS connections.
         *
         * @param sslContext the {@link SSLContext} (may be {@code null})
         * @return a client builder instance
         */
        public Builder sslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * Sets a {@link HostnameVerifier} for HTTPS connections.
         *
         * @param hostNameVerifier the {@link HostnameVerifier} (may be {@code null})
         * @return a client builder instance
         */
        public Builder hostNameVerifier(HostnameVerifier hostNameVerifier) {
            this.hostNameVerifier = hostNameVerifier;
            return this;
        }

        /**
         * Builds a {@link HttpClient} instance.
         *
         * @return a {@link HttpClient} instance
         */
        public HttpClient build() {
            return new HttpClient(this);
        }

        SSLContext getSslContext() {
            return sslContext;
        }

        HostnameVerifier getHostNameVerifier() {
            return hostNameVerifier;
        }
    }

    public static final class HttpRequest {

        static final String METHOD_POST = "POST";

        private final String method;
        private final URL url;
        private final SSLContext sslContext;
        private final HostnameVerifier hostNameVerifier;
        private List<HttpHeader> headers = new ArrayList<>();
        private Map<String, String> params = new HashMap<>();

        private HttpRequest(String method, URL url, Builder builder) {
            this.method = method;
            this.url = checkNotNullParam("url", url);
            boolean isHttps = url.getProtocol().equalsIgnoreCase("https");
            sslContext = builder.getSslContext();
            hostNameVerifier = builder.getHostNameVerifier();

            if (isHttps) {
                if (sslContext == null) {
                    throw log.httpClientSSLContextNotSpecified(url);
                }

                if (hostNameVerifier == null) {
                    throw log.httpClientHostnameVerifierNotSpecified(url);
                }
            }

        }

        /**
         * Adds a new HTTP Header to this request.
         *
         * @param header the HTTP header (must not be {@code null})
         * @return this instance
         */
        public HttpRequest header(HttpHeader header) {
            headers.add(checkNotNullParam("header", header));
            return this;
        }

        /**
         * Adds a new HTTP Parameter to this request.
         *
         * @param name the name of the HTTP Parameter (must not be {@code null})
         * @param value the value of HTTP Parameter (must not be {@code null})
         * @return this instance
         */
        public HttpRequest param(String name, String value) {
            params.put(checkNotNullParam("name", name), checkNotNullParam("value", value));
            return this;
        }

        /**
         * <p>Executes this request and notifies the specified <code>responseHandler</code> about the response sent by the server.
         *
         * <p>The <code>responseHandler</code> will also be notified about errors returned from the server. In this case,
         * implementations may expect a {@link Throwable} with additional information about the error as well a {@link InputStream}
         * with additional information returned by the server.
         *
         * @param responseHandler the response handler
         * @return the response handler result
         * @throws RuntimeException in case any unexpected error occurs when executing the request
         */
        public <R> R execute(BiFunction<InputStream, Throwable, R> responseHandler) throws RuntimeException {
            checkNotNullParam("responseHandler", responseHandler);
            HttpURLConnection connection = null;

            try {
                connection = openConnection();
                connection.setDoOutput(true);
                connection.setRequestMethod(method);
                connection.setInstanceFollowRedirects(false);

                for (HttpHeader header : headers) {
                    connection.setRequestProperty(header.getName(), header.getValue());
                }

                if (METHOD_POST.equals(method)) {
                    byte[] paramBytes = buildParameters(params);

                    try (OutputStream outputStream = connection.getOutputStream()) {
                        outputStream.write(paramBytes);
                    }
                }

                try (InputStream inputStream = new BufferedInputStream(connection.getInputStream())) {
                    return responseHandler.apply(inputStream, null);
                }
            } catch (IOException ioe) {
                InputStream errorStream = null;

                if (connection != null && connection.getErrorStream() != null) {
                    errorStream = connection.getErrorStream();

                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream))) {
                        StringBuffer response = reader.lines().reduce(new StringBuffer(), StringBuffer::append, (buffer1, buffer2) -> buffer1);
                        log.errorf(ioe, "Unexpected response from server [%s]. Response: [%s]", url, response);
                    } catch (IOException e) {
                        return responseHandler.apply(errorStream, e);
                    }
                }

                return responseHandler.apply(errorStream, ioe);
            } catch (Exception e) {
                throw log.httpClientUnexpectedResponseFromServer(e);
            }
        }

        private HttpURLConnection openConnection() throws IOException {
            try {
                log.debugf("Opening connection to server [%s]", url);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();

                if (sslContext != null) {
                    HttpsURLConnection https = (HttpsURLConnection) connection;

                    https.setSSLSocketFactory(sslContext.getSocketFactory());
                    https.setHostnameVerifier(hostNameVerifier);
                }

                return connection;
            } catch (IOException cause) {
                throw cause;
            }
        }

        private byte[] buildParameters(Map<String, String> parameters) {
            ByteStringBuilder params = new ByteStringBuilder();

            parameters.entrySet().stream().forEach(entry -> {
                if (params.length() > 0) {
                    params.append('&');
                }
                params.append(entry.getKey()).append('=').append(entry.getValue());
            });

            return params.toArray();
        }
    }

    public static final class HttpHeader {

        public static HttpHeader of(String name, String value) {
            return new HttpHeader(name, value);
        }

        public static HttpHeader contentType(String type) {
            return of("Content-Type", type);
        }

        public static HttpHeader authorizationBasic(String username, String password) {
            return of("Authorization", "Basic " + CodePointIterator.ofString(username + ":" + password).asUtf8().base64Encode().drainToString());
        }

        private String name;
        private String value;

        private HttpHeader(String name, String value) {
            this.name = name;
            this.value = value;
        }

        String getName() {
            return name;
        }

        String getValue() {
            return value;
        }
    }
}
