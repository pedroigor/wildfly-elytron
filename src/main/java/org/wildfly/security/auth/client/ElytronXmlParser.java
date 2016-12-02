/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import static javax.xml.stream.XMLStreamConstants.COMMENT;
import static javax.xml.stream.XMLStreamConstants.END_DOCUMENT;
import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static javax.xml.stream.XMLStreamConstants.PROCESSING_INSTRUCTION;
import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;
import static org.wildfly.security._private.ElytronMessages.xmlLog;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;

import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;
import org.wildfly.client.config.ClientConfiguration;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.ConfigurationXMLStreamReader;
import org.wildfly.client.config.XMLLocation;
import org.wildfly.common.function.ExceptionBiFunction;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.common.function.ExceptionUnaryOperator;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.util.ElytronAuthenticator;
import org.wildfly.security.auth.util.RegexNameRewriter;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.PublicKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.source.CredentialStoreCredentialSource;
import org.wildfly.security.credential.source.KeyStoreCredentialSource;
import org.wildfly.security.credential.source.OAuth2CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.keystore.PasswordEntry;
import org.wildfly.security.keystore.WrappingPasswordKeyStore;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;
import org.wildfly.security.password.spec.IteratedHashPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.password.util.ModularCrypt;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;
import org.wildfly.security.sasl.util.ServiceLoaderSaslClientFactory;
import org.wildfly.security.ssl.CipherSuiteSelector;
import org.wildfly.security.ssl.ProtocolSelector;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.security.util.CodePointIterator;
import org.wildfly.security.util.ServiceLoaderSupplier;
import org.wildfly.security.x500.X500;

/**
 * A parser for the Elytron XML schema.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ElytronXmlParser {

    private static final String NS_ELYTRON_1_0 = "urn:elytron:1.0";

    // authentication client document

    /**
     * Parse a Elytron authentication client configuration from a resource in the given class loader.
     *
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static SecurityFactory<AuthenticationContext> parseAuthenticationClientConfiguration() throws ConfigXMLParseException {
        final ClientConfiguration clientConfiguration = ClientConfiguration.getInstance();
        if (clientConfiguration != null) try (final ConfigurationXMLStreamReader streamReader = clientConfiguration.readConfiguration(Collections.singleton(NS_ELYTRON_1_0))) {
            return parseAuthenticationClientConfiguration(streamReader);
        } else {
            return new FixedSecurityFactory<>(AuthenticationContext.EMPTY);
        }
    }

    /**
     * Parse a Elytron authentication client configuration from a configuration XML reader.
     *
     * @param reader the XML stream reader
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static SecurityFactory<AuthenticationContext> parseAuthenticationClientConfiguration(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        if (reader.hasNext()) {
            switch (reader.nextTag()) {
                case START_ELEMENT: {
                    checkElementNamespace(reader);
                    switch (reader.getLocalName()) {
                        case "authentication-client": {
                            SecurityFactory<AuthenticationContext> futureContext = parseAuthenticationClientType(reader);
                            while (reader.hasNext()) {
                                switch (reader.next()) {
                                    case COMMENT:
                                    case PROCESSING_INSTRUCTION: {
                                        break;
                                    }
                                    case END_DOCUMENT: {
                                        return futureContext;
                                    }
                                    default: {
                                        if (reader.isWhiteSpace()) break;
                                        throw reader.unexpectedElement();
                                    }
                                }
                            }
                            return futureContext;
                        }
                        default: {
                            throw reader.unexpectedElement();
                        }
                    }
                }
                default: {
                    throw reader.unexpectedContent();
                }
            }
        }
        // Try legacy configuration next
        final ServiceLoader<LegacyConfiguration> loader = ServiceLoader.load(LegacyConfiguration.class, ElytronXmlParser.class.getClassLoader());
        final Iterator<LegacyConfiguration> iterator = loader.iterator();
        final List<LegacyConfiguration> configs = new ArrayList<>();
        for (;;) try {
            if (! iterator.hasNext()) break;
            configs.add(iterator.next());
        } catch (ServiceConfigurationError ignored) {}
        return () -> {
            for (LegacyConfiguration config : configs) {
                final AuthenticationContext context = config.getConfiguredAuthenticationContext();
                if (context != null) return context;
            }
            return AuthenticationContext.EMPTY;
        };
    }

    // authentication client types

    /**
     * Parse an XML element of type {@code authentication-client-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the authentication context factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static SecurityFactory<AuthenticationContext> parseAuthenticationClientType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        SecurityFactory<AuthenticationContext> futureContext = null;
        requireNoAttributes(reader);
        ExceptionSupplier<RuleNode<AuthenticationConfiguration>, ConfigXMLParseException> authFactory = () -> null;
        ExceptionSupplier<RuleNode<SecurityFactory<SSLContext>>, ConfigXMLParseException> sslFactory = () -> null;
        Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap = new HashMap<>();
        Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap = new HashMap<>();
        Map<String, ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException>> sslContextsMap = new HashMap<>();
        Map<String, ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException>> authenticationConfigurationsMap = new HashMap<>();
        boolean netAuthenticator = false;
        int foundBits  = 0;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "authentication-rules": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        authFactory = parseRulesType(reader, authenticationConfigurationsMap, ElytronXmlParser::parseAuthenticationRuleType);
                        break;
                    }
                    case "ssl-context-rules": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        sslFactory = parseRulesType(reader, sslContextsMap, ElytronXmlParser::parseSslContextRuleType);
                        break;
                    }
                    case "authentication-configurations": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        parseAuthenticationConfigurationsType(reader, authenticationConfigurationsMap, keyStoresMap, credentialStoresMap);
                        break;
                    }
                    case "ssl-contexts": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        parseSslContextsType(reader, sslContextsMap, keyStoresMap);
                        break;
                    }
                    case "key-stores": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        parseKeyStoresType(reader, keyStoresMap);
                        break;
                    }
                    case "net-authenticator": {
                        if (isSet(foundBits, 5)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        netAuthenticator = true;
                        parseEmptyType(reader);
                        break;
                    }
                    case "credential-stores": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        parseCredentialStoresType(reader, credentialStoresMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                if (netAuthenticator) {
                    Authenticator.setDefault(new ElytronAuthenticator());
                }
                final RuleNode<AuthenticationConfiguration> authNode = authFactory.get();
                final RuleNode<SecurityFactory<SSLContext>> sslNode = sslFactory.get();
                return () -> new AuthenticationContext(authNode, sslNode);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseAuthenticationConfigurationsType(final ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException>> authenticationConfigurationsMap, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "configuration": {
                        parseAuthenticationConfigurationType(reader, authenticationConfigurationsMap, keyStoresMap, credentialStoresMap);
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseSslContextsType(final ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException>> sslContextsMap, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "ssl-context": {
                        parseSslContextType(reader, sslContextsMap, keyStoresMap);
                        break;
                    }
                    case "default-ssl-context": {
                        final String name = parseNameType(reader);
                        sslContextsMap.put(name, () -> SSLContext::getDefault);
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static void parseSslContextType(final ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException>> sslContextsMap, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap) throws ConfigXMLParseException {
        final String name = requireSingleAttribute(reader, "name");
        if (sslContextsMap.containsKey(name)) {
            throw xmlLog.xmlDuplicateSslContextName(name, reader);
        }
        final XMLLocation location = reader.getLocation();
        int foundBits = 0;
        Supplier<Provider[]> providersSupplier = Security::getProviders;
        String providerName = null;
        CipherSuiteSelector cipherSuiteSelector = null;
        ProtocolSelector protocolSelector = null;
        PrivateKeyKeyStoreEntryCredentialFactory credentialFactory = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "key-store-ssl-certificate": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        credentialFactory = new PrivateKeyKeyStoreEntryCredentialFactory(parseKeyStoreRefType(reader, keyStoresMap), location);
                        break;
                    }
                    case "ssl-cipher-suite": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        cipherSuiteSelector = parseCipherSuiteSelectorType(reader);
                        break;
                    }
                    case "ssl-protocol": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        protocolSelector = parseProtocolSelectorNamesType(reader);
                        break;
                    }
                    case "provider-name": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        providerName = parseNameType(reader);
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "use-system-providers": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        parseEmptyType(reader);
                        // no action; this is a way of explicitly specifying the default
                        break;
                    }
                    case "use-service-loader-providers": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        final Module module = parseModuleRefType(reader);
                        providersSupplier = new ServiceLoaderSupplier<>(Provider.class, module != null ? module.getClassLoader() : ElytronXmlParser.class.getClassLoader());
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag != END_ELEMENT) {
                throw reader.unexpectedContent();
            } else {
                // ready to register!
                final Supplier<Provider[]> finalProvidersSupplier = providersSupplier;
                final ProtocolSelector finalProtocolSelector = protocolSelector;
                final CipherSuiteSelector finalCipherSuiteSelector = cipherSuiteSelector;
                final String finalProviderName = providerName;
                final PrivateKeyKeyStoreEntryCredentialFactory finalCredentialFactory = credentialFactory;
                sslContextsMap.putIfAbsent(name, () -> {
                    final SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
                    sslContextBuilder.setClientMode(true);
                    if (finalCipherSuiteSelector != null) {
                        sslContextBuilder.setCipherSuiteSelector(finalCipherSuiteSelector);
                    }
                    if (finalProtocolSelector != null) {
                        sslContextBuilder.setProtocolSelector(finalProtocolSelector);
                    }
                    if (finalCredentialFactory != null) {
                        final ConfigurationKeyManager.Builder builder = new ConfigurationKeyManager.Builder();
                        final X509CertificateChainPrivateCredential privateCredential;
                        privateCredential = finalCredentialFactory.get();
                        builder.addCredential(privateCredential);
                        sslContextBuilder.setKeyManager(builder.build());
                    }
                    sslContextBuilder.setProviderName(finalProviderName);
                    sslContextBuilder.setProviderSupplier(finalProvidersSupplier);
                    sslContextBuilder.setUseCipherSuitesOrder(true);
                    return sslContextBuilder.build();
                });
                return;
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static ExceptionUnaryOperator<RuleNode<SecurityFactory<SSLContext>>, ConfigXMLParseException> parseSslContextRuleType(final ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException>> sslContextsMap) throws ConfigXMLParseException {
        final String attributeName = "use-ssl-context";
        final String name = requireSingleAttribute(reader, attributeName);
        final XMLLocation location = reader.getLocation();
        final MatchRule rule = parseAbstractMatchRuleType(reader);
        return next -> {
            final ExceptionSupplier<SecurityFactory<SSLContext>, ConfigXMLParseException> factory = sslContextsMap.get(name);
            if (factory == null) throw xmlLog.xmlUnknownSslContextSpecified(location, name);
            return new RuleNode<>(next, rule, factory.get());
        };
    }

    static ExceptionUnaryOperator<RuleNode<AuthenticationConfiguration>, ConfigXMLParseException> parseAuthenticationRuleType(final ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException>> authenticationConfigurationsMap) throws ConfigXMLParseException {
        final String attributeName = "use-configuration";
        final String name = requireSingleAttribute(reader, attributeName);
        final XMLLocation location = reader.getLocation();
        final MatchRule rule = parseAbstractMatchRuleType(reader);
        return next -> {
            final ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException> factory = authenticationConfigurationsMap.get(name);
            if (factory == null) throw xmlLog.xmlUnknownAuthenticationConfigurationSpecified(location, name);
            return new RuleNode<>(next, rule, factory.get());
        };
    }

    static <C> ExceptionSupplier<RuleNode<C>, ConfigXMLParseException> parseRulesType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<C, ConfigXMLParseException>> configurations, ExceptionBiFunction<ConfigurationXMLStreamReader, Map<String, ExceptionSupplier<C, ConfigXMLParseException>>, ExceptionUnaryOperator<RuleNode<C>, ConfigXMLParseException>, ConfigXMLParseException> ruleParseFunction) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        final List<ExceptionUnaryOperator<RuleNode<C>, ConfigXMLParseException>> rulesList = new ArrayList<>();
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "rule": {
                        rulesList.add(ruleParseFunction.apply(reader, configurations));
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return () -> {
                    RuleNode<C> node = null;
                    final ListIterator<ExceptionUnaryOperator<RuleNode<C>, ConfigXMLParseException>> iterator = rulesList.listIterator(rulesList.size());
                    // iterate backwards to build the singly-linked list in constant time
                    while (iterator.hasPrevious()) {
                        node = iterator.previous().apply(node);
                    }
                    return node;
                };
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static void parseAuthenticationConfigurationType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<AuthenticationConfiguration, ConfigXMLParseException>> authenticationConfigurationsMap, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap) throws ConfigXMLParseException {
        final String name = requireSingleAttribute(reader, "name");
        if (authenticationConfigurationsMap.containsKey(name)) {
            throw xmlLog.xmlDuplicateAuthenticationConfigurationName(name, reader);
        }
        ExceptionUnaryOperator<AuthenticationConfiguration, ConfigXMLParseException> configuration = ignored -> AuthenticationConfiguration.EMPTY;
        int foundBits = 0;
        if (! reader.hasNext()) {
            throw reader.unexpectedDocumentEnd();
        }
        while (reader.hasNext()) {
            int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    // -- set --
                    case "set-host": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        final String hostName = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useHost(hostName));
                        break;
                    }
                    case "set-port": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        final int port = parsePortType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.usePort(port));
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "set-user-name": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        final String userName = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useName(userName));
                        break;
                    }
                    case "set-anonymous": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, AuthenticationConfiguration::useAnonymous);
                        break;
                    }
                    case "set-mechanism-realm": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        final String realm = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useRealm(realm));
                        break;
                    }
                    case "rewrite-user-name-regex": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        final NameRewriter nameRewriter = parseRegexSubstitutionType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.rewriteUser(nameRewriter));
                        break;
                    }
                    case "set-mechanism-properties": {
                        if (isSet(foundBits, 5)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        final Map<String, String> mechanismProperties = parsePropertiesType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useMechanismProperties(mechanismProperties));
                        break;
                    }
                    case "allow-all-sasl-mechanisms": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 6);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, AuthenticationConfiguration::allowAllSaslMechanisms);
                        break;
                    }
                    case "allow-sasl-mechanisms": {
                        if (isSet(foundBits, 7)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 7);
                        final String[] names = parseNamesType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.allowSaslMechanisms(names));
                        break;
                    }
                    case "forbid-sasl-mechanisms": {
                        if (isSet(foundBits, 8)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 8);
                        final String[] names = parseNamesType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.forbidSaslMechanisms(names));
                        break;
                    }
                    case "credentials": {
                        if (isSet(foundBits, 9)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 9);
                        ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSource = parseCredentialsType(reader, keyStoresMap, credentialStoresMap);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useCredentials(credentialSource.get()));
                        break;
                    }
                    case "set-authorization-name": {
                        if (isSet(foundBits, 10)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 10);
                        final String authName = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useAuthorizationName(authName));
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "use-system-providers": {
                        if (isSet(foundBits, 11)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 11);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useProviders(Security::getProviders));
                        break;
                    }
                    case "use-service-loader-providers": {
                        if (isSet(foundBits, 11)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 11);
                        final Module module = parseModuleRefType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useProviders(new ServiceLoaderSupplier<Provider>(Provider.class, module != null ? module.getClassLoader() : ElytronXmlParser.class.getClassLoader())));
                        break;
                    }
                    // these two are a <choice> which is why they share a bit #; you can have only one of them
                    case "use-provider-sasl-factory": {
                        if (isSet(foundBits, 12)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 12);
                        parseEmptyType(reader);
                        configuration = andThenOp(configuration, AuthenticationConfiguration::useSaslClientFactoryFromProviders);
                        break;
                    }
                    case "use-service-loader-sasl-factory": {
                        if (isSet(foundBits, 12)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 12);
                        final Module module = parseModuleRefType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useSaslClientFactory(new ServiceLoaderSaslClientFactory(module != null ? module.getClassLoader() : ElytronXmlParser.class.getClassLoader())));
                        break;
                    }
                    case "set-protocol": {
                        if (isSet(foundBits, 13)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 13);
                        final String protocol = parseNameType(reader);
                        configuration = andThenOp(configuration, parentConfig -> parentConfig.useProtocol(protocol));
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                final ExceptionUnaryOperator<AuthenticationConfiguration, ConfigXMLParseException> finalConfiguration = configuration;
                authenticationConfigurationsMap.put(name, () -> finalConfiguration.apply(AuthenticationConfiguration.EMPTY));
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse the XML match-rule group.  On return, the reader will be positioned either at a start tag for an element
     * that is not included in this group, or at an end tag.
     *
     * @param reader the XML reader
     * @return the parsed match rule
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static MatchRule parseAbstractMatchRuleType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        MatchRule rule = MatchRule.ALL;
        int foundBits = 0;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    // -- match --
                    case "match-no-userinfo": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        parseEmptyType(reader);
                        rule = rule.matchNoUser();
                        break;
                    }
                    case "match-userinfo": {
                        if (isSet(foundBits, 0)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 0);
                        rule = rule.matchUser(parseNameType(reader));
                        break;
                    }
                    case "match-protocol": {
                        if (isSet(foundBits, 1)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 1);
                        rule = rule.matchProtocol(parseNameType(reader));
                        break;
                    }
                    case "match-host": {
                        if (isSet(foundBits, 2)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 2);
                        rule = rule.matchHost(parseNameType(reader));
                        break;
                    }
                    case "match-path": {
                        if (isSet(foundBits, 3)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 3);
                        rule = rule.matchPath(parseNameType(reader));
                        break;
                    }
                    case "match-port": {
                        if (isSet(foundBits, 4)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 4);
                        rule = rule.matchPort(parsePortType(reader));
                        break;
                    }
                    case "match-urn": {
                        if (isSet(foundBits, 5)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 5);
                        rule = rule.matchUrnName(parseNameType(reader));
                        break;
                    }
                    case "match-domain": {
                        if (isSet(foundBits, 6)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 6);
                        rule = rule.matchLocalSecurityDomain(parseNameType(reader));
                        break;
                    }
                    case "match-abstract-type": {
                        if (isSet(foundBits, 7)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 7);
                        rule = parseMatchAbstractType(rule, reader);
                        break;
                    }
                    case "match-purpose": {
                        if (isSet(foundBits, 8)) throw reader.unexpectedElement();
                        foundBits = setBit(foundBits, 8);
                        rule = rule.matchPurposes(parseNamesType(reader));
                        break;
                    }
                    default: {
                        return rule;
                    }
                }
            } else {
                return rule;
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static MatchRule parseMatchAbstractType(final MatchRule rule, final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String authority = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "name": name = reader.getAttributeValue(i); break;
                case "authority": authority = reader.getAttributeValue(i); break;
                default: throw reader.unexpectedAttribute(i);
            }
        }
        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
        if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedElement();
        return name == null && authority == null ? rule : rule.matchAbstractType(name, authority);
    }

    private static boolean isSet(int var, int bit) {
        return (var & 1 << bit) != 0;
    }

    private static int setBit(int var, int bit) {
        return var | 1 << bit;
    }

    private static <T> UnaryOperator<T> andThenOp(UnaryOperator<T> first, UnaryOperator<T> second) {
        return t -> second.apply(first.apply(t));
    }

    private static <T, E extends Exception> ExceptionUnaryOperator<T, E> andThenOp(ExceptionUnaryOperator<T, E> first, ExceptionUnaryOperator<T, E> second) {
        return t -> second.apply(first.apply(t));
    }

    private static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseCredentialsType(final ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap) throws ConfigXMLParseException {
        ExceptionUnaryOperator<CredentialSource, ConfigXMLParseException> function = parent -> CredentialSource.NONE;
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "key-store-reference": {
                        final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> supplier = parseKeyStoreRefType(reader, keyStoresMap);
                        function = andThenOp(function, credentialSource -> credentialSource.with(new KeyStoreCredentialSource(new FixedSecurityFactory<KeyStore.Entry>(supplier.get()))));
                        break;
                    }
                    case "credential-store-reference": {
                        final ExceptionSupplier<CredentialSource, ConfigXMLParseException> supplier = parseCredentialStoreRefType(reader, credentialStoresMap);
                        function = andThenOp(function, credentialSource -> credentialSource.with(supplier.get()));
                        break;
                    }
                    case "clear-password": {
                        char[] password = parseClearPassword(reader);
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password)))));
                        break;
                    }
                    case "hashed-password": {
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new PasswordCredential(parseHashedPassword(reader)))));
                        break;
                    }
                    case "crypt-password": {
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new PasswordCredential(parseCryptPassword(reader)))));
                        break;
                    }
                    case "key-pair": {
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new KeyPairCredential(parseKeyPair(reader)))));
                        break;
                    }
                    case "certificate": {
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(parseCertificateType(reader))));
                        break;
                    }
                    case "public-key-pem": {
                        function = andThenOp(function, credentialSource -> credentialSource.with(IdentityCredentials.NONE.withCredential(new PublicKeyCredential(parsePem(reader, PublicKey.class)))));
                        break;
                    }
                    case "bearer-token": {
                        ExceptionSupplier<CredentialSource, ConfigXMLParseException> store = parseBearerTokenType(reader);
                        function = andThenOp(function, credentialSource -> credentialSource.with(store.get()));
                        break;
                    }
                    case "oauth2-bearer-token": {
                        ExceptionSupplier<CredentialSource, ConfigXMLParseException> store = parseOAuth2BearerTokenType(reader);
                        function = andThenOp(function, credentialSource -> credentialSource.with(store.get()));
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                final ExceptionUnaryOperator<CredentialSource, ConfigXMLParseException> finalFunction = function;
                return () -> finalFunction.apply(null);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static Password parseHashedPassword(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String algorithm = null;
        String hash = null;
        String salt = null;
        int iterationCount = -1;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "algorithm": {
                    algorithm = reader.getAttributeValue(i);
                    break;
                }
                case "hash": {
                    hash = reader.getAttributeValue(i);
                    break;
                }
                case "salt": {
                    salt = reader.getAttributeValue(i);
                    break;
                }
                case "iteration-count": {
                    iterationCount = reader.getIntAttributeValue(i);
                    if (iterationCount < 1) {
                        throw xmlLog.xmlInvalidIterationCount(reader, iterationCount);
                    }
                    break;
                }
                default: {
                    throw reader.unexpectedAttribute(i);
                }
            }
        }
        if (algorithm == null) throw reader.missingRequiredAttribute("", "algorithm");
        if (hash == null) throw reader.missingRequiredAttribute("", "hash");
        byte[] hashBytes = CodePointIterator.ofString(hash).base64Decode().drain();
        final PasswordSpec passwordSpec;
        if (salt != null) {
            byte[] saltBytes = CodePointIterator.ofString(salt).base64Decode().drain();
            if (iterationCount != -1) {
                passwordSpec = new IteratedSaltedHashPasswordSpec(hashBytes, saltBytes, iterationCount);
            } else {
                passwordSpec = new SaltedHashPasswordSpec(hashBytes, saltBytes);
            }
        } else {
            if (iterationCount != -1) {
                passwordSpec = new IteratedHashPasswordSpec(hashBytes, iterationCount);
            } else {
                passwordSpec = new HashPasswordSpec(hashBytes);
            }
        }
        try {
            final PasswordFactory instance = PasswordFactory.getInstance(algorithm);
            return instance.generatePassword(passwordSpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw xmlLog.xmlFailedToCreateCredential(reader.getLocation(), e);
        }
    }

    private static Password parseCryptPassword(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final String crypt = requireSingleAttribute(reader, "crypt");
        final Password password;
        try {
            password = ModularCrypt.decode(crypt);
        } catch (InvalidKeySpecException e) {
            throw xmlLog.xmlFailedToCreateCredential(reader.getLocation(), e);
        }
        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
        if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedContent();
        return password;
    }

    private static KeyPair parseKeyPair(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "private-key-pem": {
                        if (privateKey != null) throw reader.unexpectedElement();
                        privateKey = parsePem(reader, PrivateKey.class);
                        break;
                    }
                    case "public-key-pem": {
                        if (publicKey != null) throw reader.unexpectedElement();
                        publicKey = parsePem(reader, PublicKey.class);
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                if (privateKey == null) throw reader.missingRequiredElement(NS_ELYTRON_1_0, "private-key-pem");
                if (publicKey == null) throw reader.missingRequiredElement(NS_ELYTRON_1_0, "public-key-pem");
                return new KeyPair(publicKey, privateKey);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static X509CertificateChainPrivateCredential parseCertificateType(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        PrivateKey privateKey = null;
        X509Certificate[] certificates = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "private-key-pem": {
                        if (privateKey != null) throw reader.unexpectedElement();
                        privateKey = parsePem(reader, PrivateKey.class);
                        break;
                    }
                    case "pem": {
                        if (certificates != null) throw reader.unexpectedElement();
                        certificates = parseMultiPem(reader, X509Certificate.class, X509Certificate[]::new);
                        break;
                    }
                    default: {
                        throw reader.unexpectedElement();
                    }
                }
            } else if (tag == END_ELEMENT) {
                if (privateKey == null) throw reader.missingRequiredElement(NS_ELYTRON_1_0, "private-key-pem");
                if (certificates == null) throw reader.missingRequiredElement(NS_ELYTRON_1_0, "pem");
                return new X509CertificateChainPrivateCredential(privateKey, certificates);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    private static <P> P[] parseMultiPem(final ConfigurationXMLStreamReader reader, final Class<P> pemType, final IntFunction<P[]> ctor) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        if (reader.hasNext()) {
            final int next = reader.next();
            if (reader.hasText()) {
                final Iterator<PemEntry<?>> pemContent = Pem.parsePemContent(CodePointIterator.ofString(reader.getElementText()).skip(Character::isWhitespace));
                if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
                if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedContent();
                final ArrayList<P> arrayList = new ArrayList<>();
                while (pemContent.hasNext()) {
                    final PemEntry<?> pemEntry = pemContent.next();
                    final P pem = pemEntry.tryCast(pemType);
                    if (pem == null) throw xmlLog.xmlWrongPemType(reader, pemType, pemEntry.getEntry().getClass());
                    arrayList.add(pem);
                }
                if (arrayList.isEmpty()) throw xmlLog.xmlNoPemContent(reader);
                return arrayList.toArray(ctor.apply(arrayList.size()));
            } else {
                throw reader.unexpectedContent();
            }
        } else {
            throw reader.unexpectedDocumentEnd();
        }
    }

    private static <P> P parsePem(final ConfigurationXMLStreamReader reader, final Class<P> pemType) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        if (reader.hasNext()) {
            final int next = reader.next();
            if (reader.hasText()) {
                final Iterator<PemEntry<?>> pemContent = Pem.parsePemContent(CodePointIterator.ofString(reader.getElementText()).skip(Character::isWhitespace));
                if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
                if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedContent();
                if (! pemContent.hasNext()) throw xmlLog.xmlNoPemContent(reader);
                final PemEntry<?> pemEntry = pemContent.next();
                final P pem = pemEntry.tryCast(pemType);
                if (pem == null) throw xmlLog.xmlWrongPemType(reader, pemType, pemEntry.getEntry().getClass());
                return pem;
            } else {
                throw reader.unexpectedContent();
            }
        } else {
            throw reader.unexpectedDocumentEnd();
        }
    }

    /**
     * Parse an XML element of type {@code key-stores-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static void parseKeyStoresType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "key-store": {
                        parseKeyStoreType(reader, keyStoresMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code key-store-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static void parseKeyStoreType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String type = null;
        String provider = null;
        Boolean wrap = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "type": {
                    if (type != null) throw reader.unexpectedAttribute(i);
                    type = reader.getAttributeValue(i);
                    break;
                }
                case "provider": {
                    if (provider != null) throw reader.unexpectedAttribute(i);
                    provider = reader.getAttributeValue(i);
                    break;
                }
                case "name": {
                    if (name != null) throw reader.unexpectedAttribute(i);
                    name = reader.getAttributeValue(i);
                    break;
                }
                case "wrap-passwords": {
                    if (wrap != null) throw reader.unexpectedAttribute(i);
                    wrap = Boolean.valueOf(Boolean.parseBoolean(reader.getAttributeValue(i)));
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (type == null) {
            throw missingAttribute(reader, "type");
        }
        if (name == null) {
            throw missingAttribute(reader, "name");
        }
        final XMLLocation location = reader.getLocation();
        ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory = null;
        boolean gotSource = false;
        boolean gotCredential = false;

        String fileSource = null;
        String resourceSource = null;
        URI uriSource = null;

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        // group 2
                        if (! gotSource || gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        final XMLLocation nestedLocation = reader.getLocation();
                        final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> entryFactory = parseKeyStoreRefType(reader, keyStoresMap);
                        passwordFactory = () -> {
                            final KeyStore.Entry entry = entryFactory.get();
                            if (entry instanceof PasswordEntry) try {
                                final Password password = ((PasswordEntry) entry).getPassword();
                                final PasswordFactory passwordFactory1 = PasswordFactory.getInstance(password.getAlgorithm());
                                final ClearPasswordSpec passwordSpec = passwordFactory1.getKeySpec(password, ClearPasswordSpec.class);
                                return passwordSpec.getEncodedPassword();
                            } catch (GeneralSecurityException e) {
                                throw xmlLog.xmlFailedToCreateCredential(nestedLocation, e);
                            }
                            return null;
                        };
                        break;
                    }
                    case "key-store-clear-password": {
                        // group 2
                        if (! gotSource || gotCredential) {
                            throw reader.unexpectedElement();
                        }
                        gotCredential = true;
                        final char[] clearPassword = parseClearPassword(reader);
                        passwordFactory = () -> clearPassword;
                        break;
                    }
                    case "file": {
                        // group 1
                        if (gotSource) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        fileSource = parseNameType(reader);
                        break;
                    }
                    case "resource": {
                        // group 1
                        if (gotSource) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        resourceSource = parseNameType(reader);
                        break;
                    }
                    case "uri": {
                        // group 1
                        if (gotSource) {
                            throw reader.unexpectedElement();
                        }
                        gotSource = true;
                        uriSource = parseUriType(reader);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                ExceptionSupplier<KeyStore, ConfigXMLParseException> keyStoreFactory = new KeyStoreCreateFactory(provider, type, location);
                if (wrap == Boolean.TRUE) {
                    keyStoreFactory = new PasswordKeyStoreFactory(keyStoreFactory);
                }
                if (fileSource != null) {
                    keyStoreFactory = new FileLoadingKeyStoreFactory(keyStoreFactory, passwordFactory, fileSource, location);
                } else if (resourceSource != null) {
                    keyStoreFactory = new ResourceLoadingKeyStoreFactory(keyStoreFactory, passwordFactory, resourceSource, location);
                } else if (uriSource != null) {
                    keyStoreFactory = new URILoadingKeyStoreFactory(keyStoreFactory, passwordFactory, uriSource, location);
                } else {
                    // not reachable
                    throw new IllegalStateException();
                }
                keyStoresMap.put(name, keyStoreFactory);
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code kwy-store-ref-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param keyStoresMap the map of key stores to use
     * @return the key store entry factory
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> parseKeyStoreRefType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<KeyStore, ConfigXMLParseException>> keyStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        final XMLLocation location = reader.getLocation();
        String keyStoreName = null;
        String alias = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "key-store-name": {
                    if (keyStoreName != null) throw reader.unexpectedAttribute(i);
                    keyStoreName = reader.getAttributeValue(i);
                    break;
                }
                case "alias": {
                    if (alias != null) throw reader.unexpectedAttribute(i);
                    alias = reader.getAttributeValue(i);
                    break;
                }
                default:

            }
        }
        if (keyStoreName == null) {
            throw missingAttribute(reader, "key-store-name");
        }
        if (alias == null) {
            throw missingAttribute(reader, "alias");
        }
        ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> keyStoreCredential = null;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "key-store-credential": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        keyStoreCredential = parseKeyStoreRefType(reader, keyStoresMap);
                        break;
                    }
                    case "key-store-clear-password": {
                        if (keyStoreCredential != null) throw reader.unexpectedElement();
                        keyStoreCredential = () -> new PasswordEntry(ClearPassword.createRaw("clear", parseClearPassword(reader)));
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> finalKeyStoreCredential = keyStoreCredential;
                final String finalKeyStoreName = keyStoreName;
                final String finalAlias = alias;
                return () -> {
                    try {
                        final ExceptionSupplier<KeyStore, ConfigXMLParseException> keyStoreSupplier = keyStoresMap.get(finalKeyStoreName);
                        if (keyStoreSupplier == null) {
                            throw xmlLog.xmlUnknownKeyStoreSpecified(location);
                        }
                        final KeyStore.ProtectionParameter protectionParameter;
                        final KeyStore.Entry entry = finalKeyStoreCredential == null ? null : finalKeyStoreCredential.get();
                        if (entry instanceof PasswordEntry) {
                            final Password password = ((PasswordEntry) entry).getPassword();
                            final PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                            final ClearPasswordSpec spec = passwordFactory.getKeySpec(password, ClearPasswordSpec.class);
                            protectionParameter = new KeyStore.PasswordProtection(spec.getEncodedPassword());
                        } else if (entry instanceof KeyStore.SecretKeyEntry) {
                            final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                            final SecretKeyFactory instance = SecretKeyFactory.getInstance(secretKey.getAlgorithm());
                            final SecretKeySpec keySpec = (SecretKeySpec) instance.getKeySpec(secretKey, SecretKeySpec.class);
                            final byte[] encoded = keySpec.getEncoded();
                            protectionParameter = encoded == null ? null : new KeyStore.PasswordProtection(new String(encoded, StandardCharsets.UTF_8).toCharArray());
                        } else {
                            protectionParameter = null;
                        }
                        return keyStoreSupplier.get().getEntry(finalAlias, protectionParameter == null ? null : protectionParameter);
                    } catch (GeneralSecurityException e) {
                        throw xmlLog.xmlFailedToLoadKeyStoreData(location, e);
                    }
                };
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseCredentialStoreRefType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String storeName = null;
        String alias = null;
        String clearText = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "store": {
                    if (storeName != null) throw reader.unexpectedAttribute(i);
                    storeName = reader.getAttributeValue(i);
                    break;
                }
                case "alias": {
                    if (alias != null) throw reader.unexpectedAttribute(i);
                    alias = reader.getAttributeValue(i);
                    break;
                }
                case "clear-text": {
                    if (clearText != null) throw reader.unexpectedAttribute(i);
                    clearText = reader.getAttributeValue(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (! reader.hasNext()) throw reader.unexpectedDocumentEnd();
        if (reader.nextTag() != END_ELEMENT) throw reader.unexpectedContent();
        return createCredentialStoreSupplier(reader.getLocation(), storeName, alias, clearText, credentialStoresMap);
    }

    private static ExceptionSupplier<CredentialSource, ConfigXMLParseException> createCredentialStoreSupplier(final XMLLocation location, final String storeName, final String alias, final String clearText, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap) {
        return () -> {
            final ExceptionSupplier<CredentialStore, ConfigXMLParseException> supplier = credentialStoresMap.get(storeName);
            if (supplier == null) {
                throw xmlLog.xmlCredentialStoreNameNotDefined(location, storeName);
            }
            final CredentialStore credentialStore = supplier.get();
            return new CredentialStoreCredentialSource(credentialStore, alias);
        };
    }

    /**
     * Parse an XML element of type {@code credential-stores-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param credentialStoresMap the map of  credential stores to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static void parseCredentialStoresType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case NS_ELYTRON_1_0: break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    case "credential-store": {
                        parseCredentialStoreType(reader, credentialStoresMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code key-store-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param credentialStoresMap the map of  credential stores to fill
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static void parseCredentialStoreType(ConfigurationXMLStreamReader reader, final Map<String, ExceptionSupplier<CredentialStore, ConfigXMLParseException>> credentialStoresMap) throws ConfigXMLParseException {
        final XMLLocation location = reader.getLocation();
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String type = null;
        String provider = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            switch (reader.getAttributeLocalName(i)) {
                case "type": {
                    if (type != null) throw reader.unexpectedAttribute(i);
                    type = reader.getAttributeValue(i);
                    break;
                }
                case "provider": {
                    if (provider != null) throw reader.unexpectedAttribute(i);
                    provider = reader.getAttributeValue(i);
                    break;
                }
                case "name": {
                    if (name != null) throw reader.unexpectedAttribute(i);
                    name = reader.getAttributeValue(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (name == null) {
            throw missingAttribute(reader, "name");
        }

        final Map<String, String> attributesMap = new HashMap<>();
        int attributesSectionCount = 0;
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case NS_ELYTRON_1_0: break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    case "attributes": {
                        if (++attributesSectionCount > 1) throw reader.unexpectedContent();
                        parseAttributesType(reader, attributesMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                if (!credentialStoresMap.containsKey(name)) {
                    ExceptionSupplier<CredentialStore, ConfigXMLParseException> credentialStoreSecurityFactory = new CredentialStoreFactory(name, type, attributesMap, provider, location);
                    credentialStoresMap.put(name, credentialStoreSecurityFactory);
                } else {
                    throw xmlLog.duplicateCredentialStoreName(reader, name);
                }
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    // common types

    /**
     * Parse attributes {@code attributes-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param attributesMap the map to put attributes to.
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static void parseAttributesType(ConfigurationXMLStreamReader reader, final Map<String, String> attributesMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                switch (reader.getNamespaceURI()) {
                    case NS_ELYTRON_1_0: break;
                    default: throw reader.unexpectedElement();
                }
                switch (reader.getLocalName()) {
                    case "attribute": {
                        parseAttributeType(reader, attributesMap);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an attribute {@code attribute-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param attributesMap the map to put attributes to.
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    public static void parseAttributeType(ConfigurationXMLStreamReader reader, final Map<String, String> attributesMap) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        String value = null;
        for (int i = 0; i < attributeCount; i ++) {
            final String attributeNamespace = reader.getAttributeNamespace(i);
            if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
                throw reader.unexpectedAttribute(i);
            }
            switch (reader.getAttributeLocalName(i)) {
                case "name": {
                    if (name != null) throw reader.unexpectedAttribute(i);
                    name = reader.getAttributeValue(i);
                    break;
                }
                case "value": {
                    if (value != null) throw reader.unexpectedAttribute(i);
                    value = reader.getAttributeValue(i);
                    break;
                }
                default:
                    throw reader.unexpectedAttribute(i);
            }
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedContent();
            } else if (tag == END_ELEMENT) {
                if (!attributesMap.containsKey(name)) {
                    attributesMap.put(name, value);
                } else {
                    throw xmlLog.duplicateAttributeFound(reader, name);
                }
                return;
            }
            throw reader.unexpectedContent();
        }
        throw reader.unexpectedContent();
    }

    /**
     * Parse an XML element of type {@code empty-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static void parseEmptyType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        requireNoAttributes(reader);
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code name-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed name
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static String parseNameType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        return parseNameType(reader, false);
    }

    /**
     * Parse an XML element of type {@code name-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param optional is the name attribute optional?
     * @return the parsed name
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static String parseNameType(ConfigurationXMLStreamReader reader, boolean optional) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String name = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("name")) {
                name = reader.getAttributeValue(i);
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (name == null && !optional) {
            throw missingAttribute(reader, "name");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return name;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code port-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the port number (1-65535 inclusive)
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static int parsePortType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        int number = -1;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("number")) {
                String s = reader.getAttributeValue(i);
                try {
                    number = Integer.parseInt(s);
                } catch (NumberFormatException ignored) {
                    throw invalidPortNumber(reader, i);
                }
                if (number < 1 || number > 65535) {
                    throw invalidPortNumber(reader, i);
                }
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (number == -1) {
            throw missingAttribute(reader, "number");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return number;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code regex-substitution-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the regular expression based name rewriter
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static NameRewriter parseRegexSubstitutionType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        Pattern pattern = null;
        String replacement = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("pattern")) {
                pattern = Pattern.compile(reader.getAttributeValue(i));
            } else if (reader.getAttributeLocalName(i).equals("replacement")) {
                replacement = reader.getAttributeValue(i);
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (pattern == null) {
            throw missingAttribute(reader, "pattern");
        }
        if (replacement == null) {
            throw missingAttribute(reader, "replacement");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return new RegexNameRewriter(pattern, replacement, true);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code names-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the array of parsed names
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static String[] parseNamesType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String[] names = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("names")) {
                String s = reader.getAttributeValue(i);
                names = s.trim().split("\\s+");
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (names == null) {
            throw missingAttribute(reader, "names");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return names;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code uri-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed URI
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static URI parseUriType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        URI uri = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("uri")) {
                uri = reader.getURIAttributeValue(i);
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (uri == null) {
            throw missingAttribute(reader, "uri");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return uri;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code ssl-cipher-selector-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed cipher suite selector
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static CipherSuiteSelector parseCipherSuiteSelectorType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        CipherSuiteSelector selector = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("selector")) {
                selector = CipherSuiteSelector.fromString(reader.getAttributeValue(i));
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (selector == null) {
            throw missingAttribute(reader, "selector");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return selector;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code names} which yields a protocol selector from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the parsed protocol selector
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ProtocolSelector parseProtocolSelectorNamesType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        ProtocolSelector selector = ProtocolSelector.empty();
        for (String name : parseNamesType(reader)) {
            selector = selector.add(name);
        }
        return selector;
    }

    /**
     * Parse an XML element of type {@code module-ref-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the corresponding module
     * @throws ConfigXMLParseException if the resource failed to be parsed or the module is not found
     */
    static Module parseModuleRefType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String moduleName = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("module-name")) {
                moduleName = reader.getAttributeValue(i);
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }

        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                if (moduleName != null) {
                    final ModuleIdentifier identifier = ModuleIdentifier.fromString(moduleName);
                    try {
                        return Module.getModuleFromCallerModuleLoader(identifier);
                    } catch (ModuleLoadException e) {
                        throw xmlLog.xmlNoModuleFound(reader, e, identifier);
                    }
                } else {
                    return null;
                }
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code clear-password-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @return the clear password characters
     * @throws ConfigXMLParseException if the resource failed to be parsed or the module is not found
     */
    static char[] parseClearPassword(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        char[] password = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            if (reader.getAttributeLocalName(i).equals("password")) {
                password = reader.getAttributeValue(i).toCharArray();
            } else {
                throw reader.unexpectedAttribute(i);
            }
        }
        if (password == null) {
            throw missingAttribute(reader, "password");
        }
        if (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return password;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    static Map<String, String> parsePropertiesType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        if (reader.getAttributeCount() > 0) {
            throw reader.unexpectedAttribute(0);
        }

        Map<String, String> propertiesMap = new HashMap<>();

        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "property":
                        final int attributeCount = reader.getAttributeCount();
                        String key = null;
                        String value = null;
                        for (int i = 0; i < attributeCount; i++) {
                            checkAttributeNamespace(reader, i);
                            switch (reader.getAttributeLocalName(i)) {
                                case "key":
                                    if (key != null)
                                        throw reader.unexpectedAttribute(i);
                                    key = reader.getAttributeValue(i);
                                    break;
                                case "value":
                                    if (value != null)
                                        throw reader.unexpectedAttribute(i);
                                    value = reader.getAttributeValue(i);
                                    break;
                                default:
                                    throw reader.unexpectedAttribute(i);
                            }
                        }
                        if (key == null) {
                            throw missingAttribute(reader, "key");
                        }
                        if (value == null) {
                            throw missingAttribute(reader, "value");
                        }
                        propertiesMap.put(key, value);
                        if (reader.hasNext()) {
                            final int innerTag = reader.nextTag();
                            if (innerTag == START_ELEMENT) {
                                throw reader.unexpectedElement();
                            } else if (innerTag == END_ELEMENT) {
                            } else {
                                throw reader.unexpectedContent();
                            }
                        } else {
                            throw reader.unexpectedDocumentEnd();
                        }

                        break;
                    default:
                        throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return propertiesMap;
            } else {
                throw reader.unexpectedContent();
            }
        }

        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code bearer-token-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param bearerTokensMap the map of bearer tokens to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseBearerTokenType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        String value = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "value": {
                    if (value != null) throw reader.unexpectedAttribute(i);
                    value = reader.getAttributeValue(i);
                    break;
                }
                default:
            }
        }
        if (value == null) {
            throw missingAttribute(reader, "value");
        }
        final BearerTokenCredential credential = new BearerTokenCredential(value);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return () -> IdentityCredentials.NONE.withCredential(credential);
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code oauth2-bearer-token-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param bearerTokensMap the map of bearer tokens to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseOAuth2BearerTokenType(ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        URI tokenEndpointUri = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "token-endpoint-uri": {
                    if (tokenEndpointUri != null) throw reader.unexpectedAttribute(i);
                    tokenEndpointUri = reader.getURIAttributeValue(i);
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }
        if (tokenEndpointUri == null) {
            throw missingAttribute(reader, "token-endpoint-uri");
        }
        OAuth2CredentialSource.Builder builder = OAuth2CredentialSource.builder(tokenEndpointUri);
        ExceptionSupplier<CredentialSource, ConfigXMLParseException> source = () -> builder.build();
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                checkElementNamespace(reader);
                switch (reader.getLocalName()) {
                    case "resource-owner-credentials": {
                        source = parseOAuth2ResourceOwnerCredentials(reader, tokenEndpointUri);
                        break;
                    }
                    default: throw reader.unexpectedElement();
                }
            } else if (tag == END_ELEMENT) {
                return source;
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    /**
     * Parse an XML element of type {@code oauth2-bearer-token-type} from an XML reader.
     *
     * @param reader the XML stream reader
     * @param bearerTokensMap the map of bearer tokens to use
     * @throws ConfigXMLParseException if the resource failed to be parsed
     */
    static ExceptionSupplier<CredentialSource, ConfigXMLParseException> parseOAuth2ResourceOwnerCredentials(ConfigurationXMLStreamReader reader, URI tokenEndpointUri) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        URI resourceServerUri = null;
        for (int i = 0; i < attributeCount; i ++) {
            checkAttributeNamespace(reader, i);
            switch (reader.getAttributeLocalName(i)) {
                case "resource-server-uri": {
                    if (resourceServerUri != null) throw reader.unexpectedAttribute(i);
                    resourceServerUri = reader.getURIAttributeValue(i);
                    break;
                }
                default: throw reader.unexpectedAttribute(i);
            }
        }
        if (resourceServerUri == null) {
            throw missingAttribute(reader, "resource-server-uri");
        }
        OAuth2CredentialSource.Builder builder = OAuth2CredentialSource.builder(tokenEndpointUri).useResourceOwnerPassword(resourceServerUri);
        while (reader.hasNext()) {
            final int tag = reader.nextTag();
            if (tag == START_ELEMENT) {
                throw reader.unexpectedElement();
            } else if (tag == END_ELEMENT) {
                return () -> builder.build();
            } else {
                throw reader.unexpectedContent();
            }
        }
        throw reader.unexpectedDocumentEnd();
    }

    // util

    private static void checkElementNamespace(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        if (! reader.getNamespaceURI().equals(NS_ELYTRON_1_0)) {
            throw reader.unexpectedElement();
        }
    }

    private static void checkAttributeNamespace(final ConfigurationXMLStreamReader reader, final int idx) throws ConfigXMLParseException {
        final String attributeNamespace = reader.getAttributeNamespace(idx);
        if (attributeNamespace != null && ! attributeNamespace.isEmpty()) {
            throw reader.unexpectedAttribute(idx);
        }
    }

    private static void requireNoAttributes(final ConfigurationXMLStreamReader reader) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount > 0) {
            throw reader.unexpectedAttribute(0);
        }
    }

    private static String requireSingleAttribute(final ConfigurationXMLStreamReader reader, final String attributeName) throws ConfigXMLParseException {
        final int attributeCount = reader.getAttributeCount();
        if (attributeCount < 1) {
            throw reader.missingRequiredAttribute("", attributeName);
        }
        checkAttributeNamespace(reader, 0);
        if (! reader.getAttributeLocalName(0).equals(attributeName)) {
            throw reader.unexpectedAttribute(0);
        }
        if (attributeCount > 1) {
            throw reader.unexpectedAttribute(1);
        }
        return reader.getAttributeValue(0);
    }

    private static ConfigXMLParseException missingAttribute(final ConfigurationXMLStreamReader reader, final String name) {
        return reader.missingRequiredAttribute(null, name);
    }

    private static ConfigXMLParseException invalidPortNumber(final ConfigurationXMLStreamReader reader, final int index) {
        return xmlLog.xmlInvalidPortNumber(reader, reader.getAttributeValue(index), reader.getAttributeLocalName(index), reader.getName());
    }

    static final class KeyStoreCreateFactory implements ExceptionSupplier<KeyStore, ConfigXMLParseException> {
        private final String provider;
        private final String type;
        private final XMLLocation location;

        KeyStoreCreateFactory(final String provider, final String type, final XMLLocation location) {
            this.provider = provider;
            this.type = type;
            this.location = location;
        }

        public KeyStore get() throws ConfigXMLParseException {
            try {
                return provider == null ? KeyStore.getInstance(type) : KeyStore.getInstance(type, provider);
            } catch (GeneralSecurityException e) {
                throw xmlLog.xmlFailedToCreateKeyStore(location, e);
            }
        }
    }

    static final class PasswordKeyStoreFactory implements ExceptionSupplier<KeyStore, ConfigXMLParseException> {
        private final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory;

        PasswordKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory) {
            this.delegateFactory = delegateFactory;
        }

        public KeyStore get() throws ConfigXMLParseException {
            return new WrappingPasswordKeyStore(delegateFactory.get());
        }
    }

    abstract static class AbstractLoadingKeyStoreFactory implements ExceptionSupplier<KeyStore, ConfigXMLParseException> {

        protected final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory;
        protected final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory;
        protected final XMLLocation location;

        protected AbstractLoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final XMLLocation location) {
            this.delegateFactory = delegateFactory;
            this.passwordFactory = passwordFactory;
            this.location = location;
        }

        public KeyStore get() throws ConfigXMLParseException {
            try {
                KeyStore keyStore = delegateFactory.get();
                try (InputStream fis = createStream()) {
                    keyStore.load(fis, passwordFactory == null ? null : passwordFactory.get());
                }
                return keyStore;
            } catch (GeneralSecurityException | IOException e) {
                throw xmlLog.xmlFailedToLoadKeyStoreData(location, e);
            }
        }

        abstract InputStream createStream() throws IOException;
    }

    static final class FileLoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {

        private final String fileName;

        FileLoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final String fileName, final XMLLocation location) {
            super(delegateFactory, passwordFactory, location);
            this.fileName = fileName;
        }

        InputStream createStream() throws FileNotFoundException {
            return new FileInputStream(fileName);
        }
    }

    static final class ResourceLoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {

        private final String resourceName;

        ResourceLoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final String resourceName, final XMLLocation location) {
            super(delegateFactory, passwordFactory, location);
            this.resourceName = resourceName;
        }

        InputStream createStream() throws IOException {
            final ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
            final InputStream stream = contextClassLoader.getResourceAsStream(resourceName);
            if (stream == null) throw new FileNotFoundException(resourceName);
            return stream;
        }
    }

    static final class URILoadingKeyStoreFactory extends AbstractLoadingKeyStoreFactory {
        private final URI uri;

        URILoadingKeyStoreFactory(final ExceptionSupplier<KeyStore, ConfigXMLParseException> delegateFactory, final ExceptionSupplier<char[], ConfigXMLParseException> passwordFactory, final URI uri, final XMLLocation location) {
            super(delegateFactory, passwordFactory, location);
            this.uri = uri;
        }

        InputStream createStream() throws IOException {
            return uri.toURL().openStream();
        }
    }

    static final class PrivateKeyKeyStoreEntryCredentialFactory implements ExceptionSupplier<X509CertificateChainPrivateCredential, ConfigXMLParseException> {
        private final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> entrySupplier;
        private final XMLLocation location;

        PrivateKeyKeyStoreEntryCredentialFactory(final ExceptionSupplier<KeyStore.Entry, ConfigXMLParseException> entrySupplier, final XMLLocation location) {
            this.entrySupplier = entrySupplier;
            this.location = location;
        }

        public X509CertificateChainPrivateCredential get() throws ConfigXMLParseException {
            final KeyStore.Entry entry = entrySupplier.get();
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                final X509Certificate[] certificateChain = X500.asX509CertificateArray(privateKeyEntry.getCertificateChain());
                return new X509CertificateChainPrivateCredential(privateKeyEntry.getPrivateKey(), certificateChain);
            }
            throw xmlLog.xmlInvalidKeyStoreEntryType(location, "unknown", KeyStore.PrivateKeyEntry.class, entry.getClass());
        }
    }
}
