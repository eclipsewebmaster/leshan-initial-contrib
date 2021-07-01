/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless and others.
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

import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.leshan.client.bootstrap.BootstrapConsistencyChecker;
import org.eclipse.leshan.client.bootstrap.DefaultBootstrapConsistencyChecker;
import org.eclipse.leshan.client.engine.DefaultRegistrationEngineFactory;
import org.eclipse.leshan.client.engine.RegistrationEngine;
import org.eclipse.leshan.client.engine.RegistrationEngineFactory;
import org.eclipse.leshan.client.object.Device;
import org.eclipse.leshan.client.object.Security;
import org.eclipse.leshan.client.object.Server;
import org.eclipse.leshan.client.resource.LwM2mObjectEnabler;
import org.eclipse.leshan.client.resource.ObjectsInitializer;
import org.eclipse.leshan.core.LwM2mId;
import org.eclipse.leshan.core.californium.DefaultEndpointFactory;
import org.eclipse.leshan.core.californium.EndpointFactory;
import org.eclipse.leshan.core.node.LwM2mNode;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mDecoder;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mEncoder;
import org.eclipse.leshan.core.node.codec.LwM2mDecoder;
import org.eclipse.leshan.core.node.codec.LwM2mEncoder;
import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.core.request.BootstrapRequest;
import org.eclipse.leshan.core.util.Validate;

/**
 * Helper class to build and configure a Californium based Leshan Lightweight M2M client.
 */
public class LeshanClientBuilder {

    private final String endpoint;

    private InetSocketAddress localAddress;
    private List<? extends LwM2mObjectEnabler> objectEnablers;

    private NetworkConfig coapConfig;
    private Builder dtlsConfigBuilder;
    private List<Certificate> trustStore;

    private LwM2mEncoder encoder;
    private LwM2mDecoder decoder;

    private EndpointFactory endpointFactory;
    private RegistrationEngineFactory engineFactory;
    private Map<String, String> additionalAttributes;
    private Map<String, String> bsAdditionalAttributes;

    private BootstrapConsistencyChecker bootstrapConsistencyChecker;

    private ScheduledExecutorService executor;

    /**
     * Creates a new instance for setting the configuration options for a {@link LeshanClient} instance.
     * 
     * The builder is initialized with the following default values:
     * <ul>
     * <li><em>local address</em>: a local address and an ephemeral port (picked up during binding)</li>
     * <li><em>object enablers</em>:
     * <ul>
     * <li>Security(0) with one instance (DM server security): uri=<em>coap://leshan.eclipseprojects.io:5683</em>,
     * mode=NoSec</li>
     * <li>Server(1) with one instance (DM server): id=12345, lifetime=5minutes</li>
     * <li>Device(3): manufacturer=Eclipse Leshan, modelNumber=model12345, serialNumber=12345</li>
     * </ul>
     * </li>
     * </ul>
     * 
     * @param endpoint the end-point to identify the client on the server
     */
    public LeshanClientBuilder(String endpoint) {
        Validate.notEmpty(endpoint);
        this.endpoint = endpoint;
    }

    /**
     * Sets the local address to use.
     */
    public LeshanClientBuilder setLocalAddress(String hostname, int port) {
        if (hostname == null) {
            this.localAddress = new InetSocketAddress(port);
        } else {
            this.localAddress = new InetSocketAddress(hostname, port);
        }
        return this;
    }

    /**
     * Sets the list of objects enablers.
     * <p>
     * The easier way to create {@link LwM2mObjectEnabler} is to use the {@link ObjectsInitializer} but you can
     * implement your own {@link LwM2mObjectEnabler} if you need more flexibility.
     */
    public LeshanClientBuilder setObjects(List<? extends LwM2mObjectEnabler> objectEnablers) {
        this.objectEnablers = objectEnablers;
        return this;
    }

    /**
     * Set the {@link LwM2mEncoder} which will encode {@link LwM2mNode} with supported content format.
     * <p>
     * By default the {@link DefaultLwM2mEncoder} is used. It supports Text, Opaque, TLV and JSON format.
     */
    public LeshanClientBuilder setEncoder(LwM2mEncoder encoder) {
        this.encoder = encoder;
        return this;
    }

    /**
     * Set the {@link LwM2mDecoder} which will decode data in supported content format to create {@link LwM2mNode}.
     * <p>
     * By default the {@link DefaultLwM2mDecoder} is used. It supports Text, Opaque, TLV and JSON format.
     */
    public LeshanClientBuilder setDecoder(LwM2mDecoder decoder) {
        this.decoder = decoder;
        return this;
    }

    /**
     * Set the Californium/CoAP {@link NetworkConfig}.
     */
    public LeshanClientBuilder setCoapConfig(NetworkConfig config) {
        this.coapConfig = config;
        return this;
    }

    /**
     * Set the Scandium/DTLS Configuration : {@link DtlsConnectorConfig}.
     */
    public LeshanClientBuilder setDtlsConfig(DtlsConnectorConfig.Builder config) {
        this.dtlsConfigBuilder = config;
        return this;
    }

    /**
     * Set optional trust store for verifying X.509 server certificates.
     * 
     * @param trustStore List of trusted CA certificates
     */
    public LeshanClientBuilder setTrustStore(List<Certificate> trustStore) {
        this.trustStore = trustStore;
        return this;
    }

    /**
     * Advanced setter used to create custom CoAP endpoint.
     * <p>
     * An {@link UDPConnector} is expected for unsecured endpoint and a {@link DTLSConnector} is expected for secured
     * endpoint.
     * 
     * @param endpointFactory An {@link EndpointFactory}, you can extends {@link DefaultEndpointFactory}.
     * @return the builder for fluent client creation.
     */
    public LeshanClientBuilder setEndpointFactory(EndpointFactory endpointFactory) {
        this.endpointFactory = endpointFactory;
        return this;
    }

    /**
     * Set the {@link RegistrationEngineFactory} which is responsible to create the {@link RegistrationEngine}.
     * <p>
     * The {@link RegistrationEngine} is responsible to manage all the client lifecycle
     * (bootstrap/register/update/deregister ...)
     * <p>
     * By default a {@link DefaultRegistrationEngineFactory} is used. Look at this class to change some default timeout
     * value.
     * 
     * @return the builder for fluent client creation.
     */
    public LeshanClientBuilder setRegistrationEngineFactory(RegistrationEngineFactory engineFactory) {
        this.engineFactory = engineFactory;
        return this;
    }

    /**
     * Set the additionalAttributes for {@link org.eclipse.leshan.core.request.RegisterRequest}.
     */
    public LeshanClientBuilder setAdditionalAttributes(Map<String, String> additionalAttributes) {
        this.additionalAttributes = additionalAttributes;
        return this;
    }

    /**
     * Set the additionalAttributes for {@link BootstrapRequest}
     * 
     * @since 1.1
     */
    public LeshanClientBuilder setBootstrapAdditionalAttributes(Map<String, String> additionalAttributes) {
        this.bsAdditionalAttributes = additionalAttributes;
        return this;
    }

    /**
     * Set a {@link BootstrapConsistencyChecker} which is used to valid client state after a bootstrap session.
     * <p>
     * By default a {@link DefaultBootstrapConsistencyChecker} is used.
     * 
     * @return the builder for fluent client creation.
     */
    public LeshanClientBuilder setBootstrapConsistencyChecker(BootstrapConsistencyChecker checker) {
        this.bootstrapConsistencyChecker = checker;
        return this;
    }

    /**
     * Set a shared executor. This executor will be used everywhere it is possible. This is generally used when you want
     * to limit the number of thread to use or if you want to simulate a lot of clients sharing the same thread pool.
     * <p>
     * Currently UDP and DTLS receiver and sender thread could not be share meaning that you will at least consume 2
     * thread by client + the number of thread available in the shared executor (see <a
     * href=https://github.com/eclipse/californium/issues/1203>californium#1203 issue</a>)
     * <p>
     * Executor will not be shutdown automatically on {@link LeshanClient#destroy(boolean)}, this should be done
     * manually.
     * 
     * @param executor the executor to share.
     * @return the builder for fluent client creation.
     */
    public LeshanClientBuilder setSharedExecutor(ScheduledExecutorService executor) {
        this.executor = executor;
        return this;
    }

    public static NetworkConfig createDefaultNetworkConfig() {
        NetworkConfig networkConfig = new NetworkConfig();
        networkConfig.set(Keys.MID_TRACKER, "NULL");
        networkConfig.set(Keys.MAX_ACTIVE_PEERS, 10);
        networkConfig.set(Keys.PROTOCOL_STAGE_THREAD_COUNT, 1);

        return networkConfig;
    }

    /**
     * Creates an instance of {@link LeshanClient} based on the properties set on this builder.
     */
    public LeshanClient build() {
        if (localAddress == null) {
            localAddress = new InetSocketAddress(0);
        }
        if (objectEnablers == null) {
            ObjectsInitializer initializer = new ObjectsInitializer();
            initializer.setInstancesForObject(LwM2mId.SECURITY,
                    Security.noSec("coap://leshan.eclipseprojects.io:5683", 12345));
            initializer.setInstancesForObject(LwM2mId.SERVER, new Server(12345, 5 * 60));
            initializer.setInstancesForObject(LwM2mId.DEVICE,
                    new Device("Eclipse Leshan", "model12345", "12345", EnumSet.of(BindingMode.U)));
            objectEnablers = initializer.createAll();
        }
        if (encoder == null)
            encoder = new DefaultLwM2mEncoder();
        if (decoder == null)
            decoder = new DefaultLwM2mDecoder();
        if (coapConfig == null) {
            coapConfig = createDefaultNetworkConfig();
        }
        if (engineFactory == null) {
            engineFactory = new DefaultRegistrationEngineFactory();
        }
        if (endpointFactory == null) {
            endpointFactory = new DefaultEndpointFactory("LWM2M Client", true) {
                @Override
                protected Connector createSecuredConnector(DtlsConnectorConfig dtlsConfig) {
                    DTLSConnector dtlsConnector = new DTLSConnector(dtlsConfig);
                    if (executor != null) {
                        dtlsConnector.setExecutor(executor);
                    }
                    return dtlsConnector;
                }
            };
        }
        if (bootstrapConsistencyChecker == null) {
            bootstrapConsistencyChecker = new DefaultBootstrapConsistencyChecker();
        }

        // handle dtlsConfig
        if (dtlsConfigBuilder == null) {
            dtlsConfigBuilder = new DtlsConnectorConfig.Builder();
        }
        DtlsConnectorConfig incompleteConfig = dtlsConfigBuilder.getIncompleteConfig();

        // Handle secure address
        if (incompleteConfig.getAddress() == null) {
            if (localAddress == null) {
                localAddress = new InetSocketAddress(0);
            }
            dtlsConfigBuilder.setAddress(localAddress);
        } else if (localAddress != null && !localAddress.equals(incompleteConfig.getAddress())) {
            throw new IllegalStateException(String.format(
                    "Configuration conflict between LeshanBuilder and DtlsConnectorConfig.Builder for address: %s != %s",
                    localAddress, incompleteConfig.getAddress()));
        }

        // Handle active peers
        if (incompleteConfig.getMaxConnections() == null)
            dtlsConfigBuilder.setMaxConnections(coapConfig.getInt(Keys.MAX_ACTIVE_PEERS));
        if (incompleteConfig.getStaleConnectionThreshold() == null)
            dtlsConfigBuilder.setStaleConnectionThreshold(coapConfig.getLong(Keys.MAX_PEER_INACTIVITY_PERIOD));

        // define default timeout (see https://github.com/eclipse/leshan/issues/1002)
        if (incompleteConfig.getRetransmissionTimeout() == null)
            dtlsConfigBuilder.setRetransmissionTimeout(coapConfig.getInt(Keys.ACK_TIMEOUT));

        // Use only 1 thread to handle DTLS connection by default
        if (incompleteConfig.getConnectionThreadCount() == null) {
            dtlsConfigBuilder.setConnectionThreadCount(1);
        }
        // Use only 1 thread to receive DTLS data by default
        if (incompleteConfig.getReceiverThreadCount() == null) {
            dtlsConfigBuilder.setReceiverThreadCount(1);
        }

        // Deactivate SNI by default
        // TODO should we support SNI ?
        if (incompleteConfig.isSniEnabled() == null) {
            dtlsConfigBuilder.setSniEnabled(false);
        }

        return createLeshanClient(endpoint, localAddress, objectEnablers, coapConfig, dtlsConfigBuilder,
                this.trustStore, endpointFactory, engineFactory, bootstrapConsistencyChecker, additionalAttributes,
                bsAdditionalAttributes, encoder, decoder, executor);
    }

    /**
     * Create the <code>LeshanClient</code>.
     * <p>
     * You can extend <code>LeshanClientBuilder</code> and override this method to create a new builder which will be
     * able to build an extended <code>LeshanClient </code>.
     * <p>
     * See all the setters of this builder for more documentation about parameters.
     * 
     * @param endpoint The endpoint name for this client.
     * @param localAddress The local address used for unsecured connection.
     * @param objectEnablers The list of object enablers. An enabler adds to support for a given LWM2M object to the
     *        client.
     * @param coapConfig The coap config used to create {@link CoapEndpoint} and {@link CoapServer}.
     * @param dtlsConfigBuilder The dtls config used to create the {@link DTLSConnector}.
     * @param trustStore The optional trust store for verifying X.509 server certificates.
     * @param endpointFactory The factory which will create the {@link CoapEndpoint}.
     * @param engineFactory The factory which will create the {@link RegistrationEngine}.
     * @param checker Used to check if client state is consistent after a bootstrap session.
     * @param additionalAttributes Some extra (out-of-spec) attributes to add to the register request.
     * @param bsAdditionalAttributes Some extra (out-of-spec) attributes to add to the bootstrap request.
     * @param encoder used to encode request payload.
     * @param decoder used to decode response payload.
     * @param sharedExecutor an optional shared executor.
     * 
     * @return the new {@link LeshanClient}
     */
    protected LeshanClient createLeshanClient(String endpoint, InetSocketAddress localAddress,
            List<? extends LwM2mObjectEnabler> objectEnablers, NetworkConfig coapConfig, Builder dtlsConfigBuilder,
            List<Certificate> trustStore, EndpointFactory endpointFactory, RegistrationEngineFactory engineFactory,
            BootstrapConsistencyChecker checker, Map<String, String> additionalAttributes,
            Map<String, String> bsAdditionalAttributes, LwM2mEncoder encoder, LwM2mDecoder decoder,
            ScheduledExecutorService sharedExecutor) {
        return new LeshanClient(endpoint, localAddress, objectEnablers, coapConfig, dtlsConfigBuilder, trustStore,
                endpointFactory, engineFactory, checker, additionalAttributes, bsAdditionalAttributes, encoder, decoder,
                sharedExecutor);
    }
}
