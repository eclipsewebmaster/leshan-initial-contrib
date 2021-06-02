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
 *******************************************************************************/
package org.eclipse.leshan.client.californium;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.leshan.client.EndpointsManager;
import org.eclipse.leshan.client.servers.ServerIdentity;
import org.eclipse.leshan.client.servers.ServerIdentity.Role;
import org.eclipse.leshan.client.servers.ServerInfo;
import org.eclipse.leshan.core.CertificateUsage;
import org.eclipse.leshan.core.SecurityMode;
import org.eclipse.leshan.core.californium.EndpointFactory;
import org.eclipse.leshan.core.request.Identity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An {@link EndpointsManager} based on Californium(CoAP implementation) and Scandium (DTLS implementation) which
 * supports only 1 server.
 */
public class CaliforniumEndpointsManager implements EndpointsManager {

    private static final Logger LOG = LoggerFactory.getLogger(CaliforniumEndpointsManager.class);

    protected boolean started = false;

    protected ServerIdentity currentServer;
    protected CoapEndpoint currentEndpoint;

    protected Builder dtlsConfigbuilder;
    protected List<Certificate> trustStore;
    protected NetworkConfig coapConfig;
    protected InetSocketAddress localAddress;
    protected CoapServer coapServer;
    protected EndpointFactory endpointFactory;

    public CaliforniumEndpointsManager(InetSocketAddress localAddress, NetworkConfig coapConfig,
            Builder dtlsConfigBuilder, EndpointFactory endpointFactory) {
        this(localAddress, coapConfig, dtlsConfigBuilder, null, endpointFactory);
    }

    /**
     * @since 2.0
     */
    public CaliforniumEndpointsManager(InetSocketAddress localAddress, NetworkConfig coapConfig,
            Builder dtlsConfigBuilder, List<Certificate> trustStore, EndpointFactory endpointFactory) {
        this.localAddress = localAddress;
        this.coapConfig = coapConfig;
        this.dtlsConfigbuilder = dtlsConfigBuilder;
        this.trustStore = trustStore;
        this.endpointFactory = endpointFactory;
    }

    public void setCoapServer(CoapServer coapServer) {
        this.coapServer = coapServer;
    }

    @Override
    public synchronized ServerIdentity createEndpoint(ServerInfo serverInfo) {
        // Clear previous endpoint
        if (currentEndpoint != null) {
            coapServer.getEndpoints().remove(currentEndpoint);
            currentEndpoint.destroy();
        }

        // Create new endpoint
        Identity serverIdentity;
        if (serverInfo.isSecure()) {
            DtlsConnectorConfig incompleteConfig = dtlsConfigbuilder.getIncompleteConfig();
            Builder newBuilder = new Builder(incompleteConfig);

            // Support PSK
            if (serverInfo.secureMode == SecurityMode.PSK) {
                AdvancedSinglePskStore staticPskStore = new AdvancedSinglePskStore(serverInfo.pskId, serverInfo.pskKey);
                newBuilder.setAdvancedPskStore(staticPskStore);
                serverIdentity = Identity.psk(serverInfo.getAddress(), serverInfo.pskId);
                filterCipherSuites(newBuilder, dtlsConfigbuilder.getIncompleteConfig().getSupportedCipherSuites(), true,
                        false);
            } else if (serverInfo.secureMode == SecurityMode.RPK) {
                // set identity
                newBuilder.setCertificateIdentityProvider(new SingleCertificateProvider(serverInfo.privateKey, serverInfo.publicKey));
                // set RPK truststore
                final PublicKey expectedKey = serverInfo.serverPublicKey;
                NewAdvancedCertificateVerifier rpkVerifier = new StaticNewAdvancedCertificateVerifier.Builder()
                        .setTrustedRPKs(new RawPublicKeyIdentity(expectedKey)).build();
                newBuilder.setAdvancedCertificateVerifier(rpkVerifier);
                serverIdentity = Identity.rpk(serverInfo.getAddress(), expectedKey);
                filterCipherSuites(newBuilder, dtlsConfigbuilder.getIncompleteConfig().getSupportedCipherSuites(),
                        false, true);
            } else if (serverInfo.secureMode == SecurityMode.X509) {
                // set identity
                newBuilder.setCertificateIdentityProvider(new SingleCertificateProvider(serverInfo.privateKey, new Certificate[] { serverInfo.clientCertificate }));

                // LWM2M v1.1.1 - 5.2.8.7. Certificate Usage Field
                //
                // 0: Certificate usage 0 ("CA constraint")
                // - trustStore is combination of client's configured trust store and provided certificate in server
                // info
                // - must do PKIX validation with trustStore to build certPath
                // - must check that given certificate is part of certPath
                // - validate server name
                //
                // 1: Certificate usage 1 ("service certificate constraint")
                // - trustStore is client's configured trust store
                // - must do PKIX validation with trustStore
                // - target certificate must match what is provided certificate in server info
                // - validate server name
                //
                // 2: Certificate usage 2 ("trust anchor assertion")
                // - trustStore is only the provided certificate in server info
                // - must do PKIX validation with trustStore
                // - validate server name
                //
                // 3: Certificate usage 3 ("domain-issued certificate") (default mode if missing)
                // - no trustStore used in this mode
                // - target certificate must match what is provided certificate in server info
                // - validate server name

                CertificateUsage certificateUsage = serverInfo.certificateUsage != null ? serverInfo.certificateUsage
                        : CertificateUsage.DOMAIN_ISSUER_CERTIFICATE;

                if (certificateUsage == CertificateUsage.CA_CONSTRAINT) {
                    X509Certificate[] trustedCertificates = null;
                    // - trustStore is combination of client's configured trust store and provided certificate in server
                    // info
                    ArrayList<X509Certificate> newTrustedCertificatesList = new ArrayList<>();
                    if (this.trustStore != null) {
                        newTrustedCertificatesList.addAll(CertPathUtil.toX509CertificatesList(this.trustStore));
                    }
                    newTrustedCertificatesList.add((X509Certificate) serverInfo.serverCertificate);
                    trustedCertificates = newTrustedCertificatesList.toArray(new X509Certificate[0]);
                    newBuilder.setAdvancedCertificateVerifier(
                            new CaConstraintCertificateVerifier(serverInfo.serverCertificate, trustedCertificates));
                } else if (certificateUsage == CertificateUsage.SERVICE_CERTIFICATE_CONSTRAINT) {
                    X509Certificate[] trustedCertificates = null;

                    // - trustStore is client's configured trust store
                    if (this.trustStore != null) {
                        trustedCertificates = CertPathUtil.toX509CertificatesList(this.trustStore)
                                .toArray(new X509Certificate[0]);
                    }

                    newBuilder.setAdvancedCertificateVerifier(new ServiceCertificateConstraintCertificateVerifier(
                            serverInfo.serverCertificate, trustedCertificates));
                } else if (certificateUsage == CertificateUsage.TRUST_ANCHOR_ASSERTION) {
                    newBuilder.setAdvancedCertificateVerifier(new TrustAnchorAssertionCertificateVerifier(
                            (X509Certificate) serverInfo.serverCertificate));
                } else if (certificateUsage == CertificateUsage.DOMAIN_ISSUER_CERTIFICATE) {
                    newBuilder.setAdvancedCertificateVerifier(
                            new DomainIssuerCertificateVerifier(serverInfo.serverCertificate));
                }

                // TODO We set CN with '*' as we are not able to know the CN for some certificate usage and so this is
                // not used anymore to identify a server with x509.
                // See : https://github.com/eclipse/leshan/issues/992
                serverIdentity = Identity.x509(serverInfo.getAddress(), "*");
                filterCipherSuites(newBuilder, dtlsConfigbuilder.getIncompleteConfig().getSupportedCipherSuites(),
                        false, true);
            } else {
                throw new RuntimeException("Unable to create connector : unsupported security mode");
            }

            // For bootstrap no need to have DTLS role exchange
            // and so we can set DTLS Connection as client only by default.
            if (serverInfo.bootstrap && incompleteConfig.isClientOnly() == null) {
                newBuilder.setClientOnly();
            }

            currentEndpoint = endpointFactory.createSecuredEndpoint(newBuilder.build(), coapConfig, null);
        } else {
            currentEndpoint = endpointFactory.createUnsecuredEndpoint(localAddress, coapConfig, null);
            serverIdentity = Identity.unsecure(serverInfo.getAddress());
        }

        // Add new endpoint
        coapServer.addEndpoint(currentEndpoint);

        // Start endpoint if needed
        if (serverInfo.bootstrap) {
            currentServer = new ServerIdentity(serverIdentity, serverInfo.serverId, Role.LWM2M_BOOTSTRAP_SERVER);
        } else {
            currentServer = new ServerIdentity(serverIdentity, serverInfo.serverId);
        }
        if (started) {
            coapServer.start();
            try {
                currentEndpoint.start();
                LOG.info("New endpoint created for server {} at {}", currentServer.getUri(), currentEndpoint.getUri());
            } catch (

            IOException e) {
                throw new RuntimeException("Unable to start endpoint", e);
            }
        }
        return currentServer;
    }

    @Override
    public synchronized Collection<ServerIdentity> createEndpoints(Collection<? extends ServerInfo> serverInfo) {
        if (serverInfo == null || serverInfo.isEmpty())
            return null;
        else {
            // TODO support multi server
            if (serverInfo.size() > 1) {
                LOG.warn(
                        "CaliforniumEndpointsManager support only connection to 1 LWM2M server, first server will be used from the server list of {}",
                        serverInfo.size());
            }
            ServerInfo firstServer = serverInfo.iterator().next();
            Collection<ServerIdentity> servers = new ArrayList<>(1);
            servers.add(createEndpoint(firstServer));
            return servers;
        }
    }

    @Override
    public long getMaxCommunicationPeriodFor(ServerIdentity server, long lifetimeInMs) {
        // See https://github.com/OpenMobileAlliance/OMA_LwM2M_for_Developers/issues/283 to better understand.
        // TODO For DTLS, worst Handshake scenario should be taking into account too.

        int floor = 30000; // value from which we stop to adjust communication period using COAP EXCHANGE LIFETIME.

        // To be sure registration doesn't expired, update request should be send considering all CoAP retransmissions
        // and registration lifetime.
        // See https://tools.ietf.org/html/rfc7252#section-4.8.2
        long exchange_lifetime = coapConfig.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, 247);
        if (lifetimeInMs - exchange_lifetime >= floor) {
            return lifetimeInMs - exchange_lifetime;
        } else {
            LOG.warn("Too small lifetime : we advice to not use a lifetime < (COAP EXCHANGE LIFETIME + 30s)");
            // lifetime value is too short, so we do a compromise and we don't remove COAP EXCHANGE LIFETIME completely
            // We distribute the remaining lifetime range [0, exchange_lifetime + floor] on the remaining range
            // [1,floor]s.
            return lifetimeInMs * (floor - 1000) / (exchange_lifetime + floor) + 1000;
        }
    }

    @Override
    public synchronized void forceReconnection(ServerIdentity server, boolean resume) {
        // TODO support multi server
        if (server == null || !server.equals(currentServer))
            return;

        Connector connector = currentEndpoint.getConnector();
        if (connector instanceof DTLSConnector) {
            if (resume) {
                LOG.info("Clear DTLS session for resumption for server {}", server.getUri());
                ((DTLSConnector) connector).forceResumeAllSessions();
            } else {
                LOG.info("Clear DTLS session for server {}", server.getUri());
                ((DTLSConnector) connector).clearConnectionState();
            }
        }

    }

    public synchronized Endpoint getEndpoint(ServerIdentity server) {
        // TODO support multi server
        if (server != null && server.equals(currentServer) && currentEndpoint.isStarted())
            return currentEndpoint;
        return null;
    }

    public synchronized ServerIdentity getServerIdentity(Endpoint endpoint, InetSocketAddress serverAddress) {
        // TODO support multi server

        // knowing used CoAP endpoint we should be able to know the server identity because :
        // - we create 1 CoAP endpoint by server.
        // - the dtls configuration ensure that only server with expected credential is able to talk.
        // (see https://github.com/eclipse/leshan/issues/992 for more details)
        if (endpoint != null && endpoint.equals(currentEndpoint) && currentEndpoint.isStarted()) {
            // For UDP (not secure) endpoint we also check socket address as anybody send data to this kind of endpoint.
            if (currentEndpoint.getConnector().getProtocol() == "UDP"
                    && !currentServer.getIdentity().getPeerAddress().equals(serverAddress)) {
                return null;
            }
            return currentServer;
        }
        return null;
    }

    @Override
    public synchronized void start() {
        if (started)
            return;
        started = true;

        // we don't have any endpoint so nothing to start
        if (currentEndpoint == null)
            return;

        coapServer.start();
    }

    @Override
    public synchronized void stop() {
        if (!started)
            return;
        started = false;

        // If we have no endpoint this means that we never start coap server
        if (currentEndpoint == null)
            return;

        coapServer.stop();
    }

    @Override
    public synchronized void destroy() {
        if (started)
            started = false;

        coapServer.destroy();
    }

    private void filterCipherSuites(Builder dtlsConfigurationBuilder, List<CipherSuite> ciphers, boolean psk,
            boolean requireServerCertificateMessage) {
        if (ciphers == null)
            return;

        List<CipherSuite> filteredCiphers = new ArrayList<>();
        for (CipherSuite cipher : ciphers) {
            if (psk && cipher.isPskBased()) {
                filteredCiphers.add(cipher);
            } else if (requireServerCertificateMessage && cipher.requiresServerCertificateMessage()) {
                filteredCiphers.add(cipher);
            }
        }
        dtlsConfigurationBuilder.setSupportedCipherSuites(filteredCiphers);
    }
}
