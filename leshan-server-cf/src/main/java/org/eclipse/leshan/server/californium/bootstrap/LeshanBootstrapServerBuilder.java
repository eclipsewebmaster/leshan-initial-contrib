/*******************************************************************************
 * Copyright (c) 2017 Sierra Wireless and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *     Sierra Wireless - initial API and implementation
 *     Achim Kraus (Bosch Software Innovations GmbH) - use CoapEndpointBuilder
 *******************************************************************************/
package org.eclipse.leshan.server.californium.bootstrap;

import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.x509.BridgeCertificateVerifier;
import org.eclipse.leshan.core.LwM2m;
import org.eclipse.leshan.core.californium.DefaultEndpointFactory;
import org.eclipse.leshan.core.californium.EndpointFactory;
import org.eclipse.leshan.core.node.LwM2mNode;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mDecoder;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mEncoder;
import org.eclipse.leshan.core.node.codec.LwM2mDecoder;
import org.eclipse.leshan.core.node.codec.LwM2mEncoder;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig;
import org.eclipse.leshan.server.bootstrap.BootstrapConfigStore;
import org.eclipse.leshan.server.bootstrap.BootstrapConfigStoreTaskProvider;
import org.eclipse.leshan.server.bootstrap.BootstrapHandler;
import org.eclipse.leshan.server.bootstrap.BootstrapHandlerFactory;
import org.eclipse.leshan.server.bootstrap.BootstrapSessionListener;
import org.eclipse.leshan.server.bootstrap.BootstrapSessionManager;
import org.eclipse.leshan.server.bootstrap.DefaultBootstrapHandler;
import org.eclipse.leshan.server.bootstrap.DefaultBootstrapSessionManager;
import org.eclipse.leshan.server.bootstrap.InMemoryBootstrapConfigStore;
import org.eclipse.leshan.server.bootstrap.LwM2mBootstrapRequestSender;
import org.eclipse.leshan.server.model.LwM2mBootstrapModelProvider;
import org.eclipse.leshan.server.model.StandardBootstrapModelProvider;
import org.eclipse.leshan.server.security.BootstrapSecurityStore;
import org.eclipse.leshan.server.security.SecurityChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class helping you to build and configure a Californium based Leshan Bootstrap Lightweight M2M server.
 * <p>
 * Usage: create it, call the different setters for changing the configuration and then call the {@link #build()} method
 * for creating the {@link LeshanBootstrapServer} ready to operate.
 */
public class LeshanBootstrapServerBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(LeshanBootstrapServerBuilder.class);

    private InetSocketAddress localAddress;
    private InetSocketAddress localAddressSecure;
    private BootstrapConfigStore configStore;
    private BootstrapSecurityStore securityStore;
    private BootstrapSessionManager sessionManager;
    private BootstrapHandlerFactory bootstrapHandlerFactory;

    private LwM2mBootstrapModelProvider modelProvider;
    private NetworkConfig coapConfig;
    private Builder dtlsConfigBuilder;

    private LwM2mEncoder encoder;
    private LwM2mDecoder decoder;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private X509Certificate[] certificateChain;
    private Certificate[] trustedCertificates;

    private EndpointFactory endpointFactory;
    private boolean noSecuredEndpoint;
    private boolean noUnsecuredEndpoint;

    /**
     * Set the address/port for unsecured CoAP communication (<code>coap://</code>).
     * <p>
     * By default a wildcard address and the default CoAP port(5683) is used.
     * 
     * @param hostname The address to bind. If null wildcard address is used.
     * @param port A valid port value is between 0 and 65535. A port number of zero will let the system pick up an
     *        ephemeral port in a bind operation.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setLocalAddress(String hostname, int port) {
        if (hostname == null) {
            this.localAddress = new InetSocketAddress(port);
        } else {
            this.localAddress = new InetSocketAddress(hostname, port);
        }
        return this;
    }

    /**
     * Set the address for unsecured CoAP communication (<code>coap://</code>).
     * <p>
     * By default a wildcard address and the default CoAP port(5683) is used.
     * 
     * @param localAddress the socket address for <code>coap://</code>.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setLocalAddress(InetSocketAddress localAddress) {
        this.localAddress = localAddress;
        return this;
    }

    /**
     * Set the address/port for secured CoAP over DTLS communication (<code>coaps://</code>).
     * <p>
     * By default a wildcard address and the default CoAPs port(5684) is used.
     * 
     * @param hostname The address to bind. If null wildcard address is used.
     * @param port A valid port value is between 0 and 65535. A port number of zero will let the system pick up an
     *        ephemeral port in a bind operation.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setLocalSecureAddress(String hostname, int port) {
        if (hostname == null) {
            this.localAddressSecure = new InetSocketAddress(port);
        } else {
            this.localAddressSecure = new InetSocketAddress(hostname, port);
        }
        return this;
    }

    /**
     * Set the address for secured CoAP over DTLS communication Server (<code>coaps://</code>).
     * <p>
     * By default a wildcard address and the default CoAP port(5684) is used.
     * 
     * @param localSecureAddress the socket address for <code>coaps://</code>.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setLocalSecureAddress(InetSocketAddress localSecureAddress) {
        this.localAddressSecure = localSecureAddress;
        return this;
    }

    /**
     * Set the {@link PublicKey} of the server which will be used for Raw Public Key DTLS authentication.
     * <p>
     * This should be used for RPK support only.
     * <p>
     * Setting <code>publicKey</code> and <code>privateKey</code> will enable RawPublicKey DTLS authentication, see also
     * {@link LeshanBootstrapServerBuilder#setPrivateKey(PrivateKey)}.
     * 
     * @param publicKey the Raw Public Key of the bootstrap server.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    /**
     * Set the CertificateChain of the server which will be used for X.509 DTLS authentication.
     * <p>
     * Setting <code>publicKey</code> and <code>privateKey</code> will enable RPK and X.509 DTLS authentication, see
     * also {@link LeshanBootstrapServerBuilder#setPrivateKey(PrivateKey)}.
     * <p>
     * For RPK the public key will be extracted from the first X.509 certificate of the certificate chain. If you only
     * need RPK support, use {@link LeshanBootstrapServerBuilder#setPublicKey(PublicKey)} instead.
     * <p>
     * If you want to deactivate RPK mode, look at
     * {@link LeshanBootstrapServerBuilder#setDtlsConfig(org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder)}
     * and {@link Builder#setTrustCertificateTypes(CertificateType...)}
     * 
     * @param certificateChain the certificate chain of the bootstrap server.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public <T extends X509Certificate> LeshanBootstrapServerBuilder setCertificateChain(T[] certificateChain) {
        this.certificateChain = certificateChain;
        return this;
    }

    /**
     * Set the {@link PrivateKey} of the server which will be used for RawPublicKey(RPK) and/or X.509 DTLS
     * authentication.
     * 
     * @param privateKey the Private Key of the bootstrap server.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    /**
     * The list of trusted certificates used to authenticate devices using X.509 DTLS authentication.
     * <p>
     * If you need more complex/dynamic trust behavior, look at
     * {@link LeshanBootstrapServerBuilder#setDtlsConfig(org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder)}
     * and {@link Builder#setCertificateVerifier(org.eclipse.californium.scandium.dtls.x509.CertificateVerifier)}
     * instead.
     * 
     * @param trustedCertificates certificates trusted by the bootstrap server.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public <T extends Certificate> LeshanBootstrapServerBuilder setTrustedCertificates(T[] trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
        return this;
    }

    /**
     * Set the {@link BootstrapConfigStore} containing bootstrap configuration to apply to each devices.
     * <p>
     * By default an {@link InMemoryBootstrapConfigStore} is used.
     * <p>
     * See {@link BootstrapConfig} to see what is could be done during a bootstrap session.
     * 
     * @param configStore the bootstrap configuration store.
     * @return the builder for fluent Bootstrap Server creation.
     * 
     */
    public LeshanBootstrapServerBuilder setConfigStore(BootstrapConfigStore configStore) {
        this.configStore = configStore;
        return this;
    }

    /**
     * Set the {@link BootstrapSecurityStore} which contains data needed to authenticate devices.
     * <p>
     * WARNING: without security store all devices will be accepted which is not really recommended in production
     * environnement.
     * <p>
     * There is not default implementation.
     * 
     * @param securityStore the security store used to authenticate devices.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setSecurityStore(BootstrapSecurityStore securityStore) {
        this.securityStore = securityStore;
        return this;
    }

    /**
     * Advanced setter used to define {@link BootstrapSessionManager}.
     * <p>
     * See {@link BootstrapSessionManager} and {@link DefaultBootstrapSessionManager} for more details.
     * 
     * @param sessionManager the manager responsible to handle bootstrap session.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setSessionManager(BootstrapSessionManager sessionManager) {
        this.sessionManager = sessionManager;
        return this;
    }

    /**
     * Advanced setter used to customize default bootstrap server behavior.
     * <p>
     * If default bootstrap server behavior is not flexible enough, you can create your own {@link BootstrapHandler} by
     * inspiring yourself from {@link DefaultBootstrapHandler}.
     * 
     * @param bootstrapHandlerFactory the factory used to create {@link BootstrapHandler}.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setBootstrapHandlerFactory(BootstrapHandlerFactory bootstrapHandlerFactory) {
        this.bootstrapHandlerFactory = bootstrapHandlerFactory;
        return this;
    }

    /**
     * <p>
     * Set your {@link LwM2mBootstrapModelProvider} implementation.
     * </p>
     * By default the {@link StandardBootstrapModelProvider}.
     * 
     */
    public LeshanBootstrapServerBuilder setObjectModelProvider(LwM2mBootstrapModelProvider objectModelProvider) {
        this.modelProvider = objectModelProvider;
        return this;
    }

    /**
     * <p>
     * Set the {@link LwM2mEncoder} which will encode {@link LwM2mNode} with supported content format.
     * </p>
     * By default the {@link DefaultLwM2mEncoder} is used. It supports Text, Opaque, TLV and JSON format.
     */
    public LeshanBootstrapServerBuilder setEncoder(LwM2mEncoder encoder) {
        this.encoder = encoder;
        return this;
    }

    /**
     * <p>
     * Set the {@link LwM2mDecoder} which will decode data in supported content format to create {@link LwM2mNode}.
     * </p>
     * By default the {@link DefaultLwM2mDecoder} is used. It supports Text, Opaque, TLV and JSON format.
     */
    public LeshanBootstrapServerBuilder setDecoder(LwM2mDecoder decoder) {
        this.decoder = decoder;
        return this;
    }

    /**
     * Set the CoAP/Californium {@link NetworkConfig}.
     * <p>
     * For advanced CoAP setting, see {@link Keys} for more details.
     * 
     * @param coapConfig the CoAP configuration.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setCoapConfig(NetworkConfig coapConfig) {
        this.coapConfig = coapConfig;
        return this;
    }

    /**
     * Set the DTLS/Scandium {@link DtlsConnectorConfig}.
     * <p>
     * For advanced DTLS setting.
     * 
     * @param dtlsConfig the DTLS configuration builder.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setDtlsConfig(Builder dtlsConfig) {
        this.dtlsConfigBuilder = dtlsConfig;
        return this;
    }

    /**
     * Advanced setter used to create custom CoAP endpoint.
     * <p>
     * An {@link UDPConnector} is expected for unsecured endpoint and a {@link DTLSConnector} is expected for secured
     * endpoint.
     * 
     * @param endpointFactory An {@link EndpointFactory}, you can extends {@link DefaultEndpointFactory}.
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder setEndpointFactory(EndpointFactory endpointFactory) {
        this.endpointFactory = endpointFactory;
        return this;
    }

    /**
     * Deactivate unsecured CoAP endpoint, meaning that <code>coap://</code> communication will be impossible.
     * 
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder disableUnsecuredEndpoint() {
        this.noUnsecuredEndpoint = true;
        return this;
    }

    /**
     * Deactivate secured CoAP endpoint (DTLS), meaning that <code>coaps://</code> communication will be impossible.
     * 
     * @return the builder for fluent Bootstrap Server creation.
     */
    public LeshanBootstrapServerBuilder disableSecuredEndpoint() {
        this.noSecuredEndpoint = true;
        return this;
    }

    /**
     * Create the default CoAP/Californium {@link NetworkConfig} used by the builder.
     * <p>
     * It could be used as a base to create a custom CoAP configuration, then use it with
     * {@link #setCoapConfig(NetworkConfig)}
     * 
     * @return the default CoAP config.
     */
    public NetworkConfig createDefaultNetworkConfig() {
        NetworkConfig networkConfig = new NetworkConfig();
        networkConfig.set(Keys.MID_TRACKER, "NULL");
        return networkConfig;
    }

    /**
     * Create the {@link LeshanBootstrapServer}.
     * <p>
     * Next step will be to start it : {@link LeshanBootstrapServer#start()}.
     * 
     * @return the LWM2M Bootstrap server.
     * @throws IllegalStateException if builder configuration is not consistent.
     */
    public LeshanBootstrapServer build() {
        if (localAddress == null)
            localAddress = new InetSocketAddress(LwM2m.DEFAULT_COAP_PORT);
        if (bootstrapHandlerFactory == null)
            bootstrapHandlerFactory = new BootstrapHandlerFactory() {
                @Override
                public BootstrapHandler create(LwM2mBootstrapRequestSender sender,
                        BootstrapSessionManager sessionManager, BootstrapSessionListener listener) {
                    return new DefaultBootstrapHandler(sender, sessionManager, listener);
                }
            };
        if (configStore == null) {
            configStore = new InMemoryBootstrapConfigStore();
        } else if (sessionManager != null) {
            LOG.warn("configStore is set but you also provide a custom SessionManager so this store will not be used");
        }
        if (modelProvider == null) {
            modelProvider = new StandardBootstrapModelProvider();
        } else if (sessionManager != null) {
            LOG.warn(
                    "modelProvider is set but you also provide a custom SessionManager so this provider will not be used");
        }
        if (sessionManager == null) {
            sessionManager = new DefaultBootstrapSessionManager(securityStore, new SecurityChecker(),
                    new BootstrapConfigStoreTaskProvider(configStore), modelProvider);
        }
        if (coapConfig == null) {
            coapConfig = createDefaultNetworkConfig();
        }
        if (endpointFactory == null) {
            endpointFactory = new DefaultEndpointFactory("LWM2M BS Server", false);
        }
        if (encoder == null)
            encoder = new DefaultLwM2mEncoder();
        if (decoder == null)
            decoder = new DefaultLwM2mDecoder();

        // handle dtlsConfig
        DtlsConnectorConfig dtlsConfig = null;
        if (!noSecuredEndpoint && shouldTryToCreateSecureEndpoint()) {
            if (dtlsConfigBuilder == null) {
                dtlsConfigBuilder = new DtlsConnectorConfig.Builder();
            }
            // Set default DTLS setting for Leshan unless user change it.
            DtlsConnectorConfig incompleteConfig = dtlsConfigBuilder.getIncompleteConfig();

            // Handle PSK Store
            if (incompleteConfig.getAdvancedPskStore() != null) {
                LOG.warn(
                        "PskStore should be automatically set by Leshan. Using a custom implementation is not advised.");
            } else if (securityStore != null) {
                dtlsConfigBuilder.setAdvancedPskStore(new LwM2mBootstrapPskStore(securityStore));
            }

            // Handle secure address
            if (incompleteConfig.getAddress() == null) {
                if (localAddressSecure == null) {
                    localAddressSecure = new InetSocketAddress(LwM2m.DEFAULT_COAP_SECURE_PORT);
                }
                dtlsConfigBuilder.setAddress(localAddressSecure);
            } else if (localAddressSecure != null && !localAddressSecure.equals(incompleteConfig.getAddress())) {
                throw new IllegalStateException(String.format(
                        "Configuration conflict between LeshanBuilder and DtlsConnectorConfig.Builder for secure address: %s != %s",
                        localAddressSecure, incompleteConfig.getAddress()));
            }

            // Handle active peers
            if (incompleteConfig.getMaxConnections() == null)
                dtlsConfigBuilder.setMaxConnections(coapConfig.getInt(Keys.MAX_ACTIVE_PEERS));
            if (incompleteConfig.getStaleConnectionThreshold() == null)
                dtlsConfigBuilder.setStaleConnectionThreshold(coapConfig.getLong(Keys.MAX_PEER_INACTIVITY_PERIOD));

            // define default timeout (see https://github.com/eclipse/leshan/issues/1002)
            if (incompleteConfig.getRetransmissionTimeout() == null)
                dtlsConfigBuilder.setRetransmissionTimeout(coapConfig.getInt(Keys.ACK_TIMEOUT));

            if (privateKey != null) {
                // check conflict for private key
                if (incompleteConfig.getPrivateKey() != null && !incompleteConfig.getPrivateKey().equals(privateKey)) {
                    throw new IllegalStateException(String.format(
                            "Configuration conflict between LeshanBuilder and DtlsConnectorConfig.Builder for private key: %s != %s",
                            privateKey, incompleteConfig.getPrivateKey()));
                }

                // if in raw key mode and not in X.509 set the raw keys
                if (certificateChain == null && publicKey != null) {
                    if (incompleteConfig.getPublicKey() != null && !incompleteConfig.getPublicKey().equals(publicKey)) {
                        throw new IllegalStateException(String.format(
                                "Configuration conflict between LeshanBuilder and DtlsConnectorConfig.Builder for public key: %s != %s",
                                publicKey, incompleteConfig.getPublicKey()));
                    }
                    dtlsConfigBuilder.setIdentity(privateKey, publicKey);
                }
                // if in X.509 mode set the private key, certificate chain, public key is extracted from the certificate
                if (certificateChain != null && certificateChain.length > 0) {
                    if (incompleteConfig.getCertificateChain() != null
                            && !Arrays.asList(certificateChain).equals(incompleteConfig.getCertificateChain())) {
                        throw new IllegalStateException(String.format(
                                "Configuration conflict between LeshanBuilder and DtlsConnectorConfig.Builder for certificate chain: %s != %s",
                                Arrays.toString(certificateChain), incompleteConfig.getCertificateChain()));
                    }

                    dtlsConfigBuilder.setIdentity(privateKey, certificateChain, CertificateType.X_509,
                            CertificateType.RAW_PUBLIC_KEY);
                }

                // handle trusted certificates or RPK
                if (incompleteConfig.getAdvancedCertificateVerifier() != null) {
                    if (trustedCertificates != null) {
                        throw new IllegalStateException(
                                "Configuration conflict between LeshanBuilder and DtlsConnectorConfig.Builder: if a AdvancedCertificateVerifier is set, trustedCertificates must not be set.");
                    }
                } else {
                    BridgeCertificateVerifier.Builder verifierBuilder = new BridgeCertificateVerifier.Builder();
                    if (incompleteConfig.getRpkTrustStore() != null) {
                        verifierBuilder.setTrustedRPKs(incompleteConfig.getRpkTrustStore());
                    } else {
                        // by default trust all RPK
                        verifierBuilder.setTrustAllRPKs();
                    }
                    if (incompleteConfig.getTrustStore() != null) {
                        if (trustedCertificates != null
                                && !Arrays.equals(trustedCertificates, incompleteConfig.getTrustStore())) {
                            throw new IllegalStateException(String.format(
                                    "Configuration conflict between LeshanBuilder and DtlsConnectorConfig.Builder for trusted Certificates (trustStore) : \n%s != \n%s",
                                    Arrays.toString(trustedCertificates),
                                    Arrays.toString(incompleteConfig.getTrustStore())));
                        }
                        verifierBuilder.setTrustedCertificates(incompleteConfig.getTrustStore());
                    } else {
                        if (trustedCertificates != null) {
                            verifierBuilder.setTrustedCertificates(trustedCertificates);
                        }
                    }
                    if (incompleteConfig.getCertificateVerifier() != null) {
                        if (trustedCertificates != null) {
                            throw new IllegalStateException(
                                    "Configuration conflict between LeshanBuilder and DtlsConnectorConfig.Builder: if a CertificateVerifier is set, trustedCertificates must not be set.");
                        }
                        verifierBuilder.setCertificateVerifier(incompleteConfig.getCertificateVerifier());
                    }
                    dtlsConfigBuilder.setAdvancedCertificateVerifier(verifierBuilder.build());
                }
            }

            // Bootstrap Server acts as Server only : It does not need to initiate handshake
            if (incompleteConfig.isServerOnly() == null) {
                dtlsConfigBuilder.setServerOnly(true);
            }

            // Deactivate SNI by default
            // TODO should we support SNI ?
            if (incompleteConfig.isSniEnabled() == null) {
                dtlsConfigBuilder.setSniEnabled(false);
            }

            // we try to build the dtlsConfig, if it fail we will just not create the secured endpoint
            try {
                dtlsConfig = dtlsConfigBuilder.build();
            } catch (IllegalStateException e) {
                LOG.warn("Unable to create DTLS config and so secured endpoint.", e);
            }
        }

        CoapEndpoint unsecuredEndpoint = null;
        if (!noUnsecuredEndpoint) {
            unsecuredEndpoint = endpointFactory.createUnsecuredEndpoint(localAddress, coapConfig, null);
        }

        CoapEndpoint securedEndpoint = null;
        if (!noSecuredEndpoint && dtlsConfig != null) {
            securedEndpoint = endpointFactory.createSecuredEndpoint(dtlsConfig, coapConfig, null);
        }

        if (securedEndpoint == null && unsecuredEndpoint == null) {
            throw new IllegalStateException(
                    "All CoAP enpoints are deactivated, at least one endpoint should be activated");
        }

        return createBootstrapServer(unsecuredEndpoint, securedEndpoint, sessionManager, bootstrapHandlerFactory,
                coapConfig, encoder, decoder);
    }

    /**
     * @return true if we should try to create a secure endpoint on {@link #build()}
     */
    protected boolean shouldTryToCreateSecureEndpoint() {
        return dtlsConfigBuilder != null || certificateChain != null || privateKey != null || publicKey != null
                || securityStore != null || trustedCertificates != null;
    }

    /**
     * Create the <code>LeshanBootstrapServer</code>.
     * <p>
     * You can extend <code>LeshanBootstrapServerBuilder</code> and override this method to create a new builder which
     * will be able to build an extended <code>LeshanBootstrapServer</code>.
     * 
     * @param unsecuredEndpoint CoAP endpoint used for <code>coap://</code> communication.
     * @param securedEndpoint CoAP endpoint used for <code>coaps://</code> communication.
     * @param bsSessionManager the manager responsible to handle bootstrap session.
     * @param bsHandlerFactory the factory used to create {@link BootstrapHandler}.
     * @param coapConfig the CoAP configuration.
     * @param decoder decoder used to decode response payload.
     * @param encoder encode used to encode request payload.
     * @return the LWM2M Bootstrap server.
     */
    protected LeshanBootstrapServer createBootstrapServer(CoapEndpoint unsecuredEndpoint, CoapEndpoint securedEndpoint,
            BootstrapSessionManager bsSessionManager, BootstrapHandlerFactory bsHandlerFactory,
            NetworkConfig coapConfig, LwM2mEncoder encoder, LwM2mDecoder decoder) {
        return new LeshanBootstrapServer(unsecuredEndpoint, securedEndpoint, bsSessionManager, bsHandlerFactory,
                coapConfig, encoder, decoder);
    }
}
