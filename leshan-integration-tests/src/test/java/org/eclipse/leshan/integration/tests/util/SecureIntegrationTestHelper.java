/*******************************************************************************
 * Copyright (c) 2013-2015 Sierra Wireless and others.
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
 *     Zebra Technologies - initial API and implementation
 *******************************************************************************/

package org.eclipse.leshan.integration.tests.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.leshan.client.californium.LeshanClientBuilder;
import org.eclipse.leshan.client.californium.X509Util;
import org.eclipse.leshan.client.engine.DefaultRegistrationEngineFactory;
import org.eclipse.leshan.client.object.Device;
import org.eclipse.leshan.client.object.Security;
import org.eclipse.leshan.client.object.Server;
import org.eclipse.leshan.client.resource.DummyInstanceEnabler;
import org.eclipse.leshan.client.resource.LwM2mObjectEnabler;
import org.eclipse.leshan.client.resource.ObjectsInitializer;
import org.eclipse.leshan.core.CertificateUsage;
import org.eclipse.leshan.core.LwM2mId;
import org.eclipse.leshan.core.californium.EndpointFactory;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.core.util.X509CertUtil;
import org.eclipse.leshan.server.californium.LeshanServerBuilder;
import org.eclipse.leshan.server.security.DefaultAuthorizer;
import org.eclipse.leshan.server.security.EditableSecurityStore;
import org.eclipse.leshan.server.security.InMemorySecurityStore;
import org.eclipse.leshan.server.security.SecurityChecker;
import org.eclipse.leshan.server.security.SecurityStore;

public class SecureIntegrationTestHelper extends IntegrationTestHelper {

    public static final String GOOD_PSK_ID = "Good_Client_identity";
    public static final byte[] GOOD_PSK_KEY = Hex.decodeHex("73656372657450534b".toCharArray());
    public static final String GOOD_ENDPOINT = "good_endpoint";
    public static final String BAD_PSK_ID = "Bad_Client_identity";
    public static final byte[] BAD_PSK_KEY = Hex.decodeHex("010101010101010101".toCharArray());
    public static final String BAD_ENDPOINT = "bad_endpoint";
    private SinglePSKStore singlePSKStore;
    protected SecurityStore securityStore;

    public final PublicKey clientPublicKey; // client public key used for RPK
    public final PrivateKey clientPrivateKey; // client private key used for RPK
    public final PublicKey serverPublicKey; // server public key used for RPK
    public final PrivateKey serverPrivateKey; // server private key used for RPK

    // client private key used for X509
    public final PrivateKey clientPrivateKeyFromCert;
    // mfg client private key used for X509
    public final PrivateKey mfgClientPrivateKeyFromCert;
    // server private key used for X509
    public final PrivateKey serverPrivateKeyFromCert;
    // server private key used for X509
    public final PrivateKey serverIntPrivateKeyFromCert;
    // client certificate signed by rootCA with a good CN (CN start by leshan_integration_test)
    public final X509Certificate clientX509Cert;
    // client certificate signed by rootCA but with bad CN (CN does not start by leshan_integration_test)
    public final X509Certificate clientX509CertWithBadCN;
    // client certificate self-signed with a good CN (CN start by leshan_integration_test)
    public final X509Certificate clientX509CertSelfSigned;
    // client certificate signed by another CA (not rootCA) with a good CN (CN start by leshan_integration_test)
    public final X509Certificate clientX509CertNotTrusted;
    // client certificate signed by manufacturer CA's with a good CN
    // (CN=urn:dev:ops:32473-IoT_Device-K1234567,O=Manufacturer)
    public final X509Certificate[] mfgClientX509CertChain;
    // server certificate signed by rootCA
    public final X509Certificate serverX509Cert;
    // server certificate signed by intermediateCA
    public final X509Certificate[] serverIntX509CertChain;
    // self-signed server certificate
    public final X509Certificate serverX509CertSelfSigned;
    // self-signed server certificate
    public final X509Certificate serverIntX509CertSelfSigned;
    // rootCA used by the server
    public final X509Certificate rootCAX509Cert;
    // certificates trustedby the server (should contain rootCA)
    public final Certificate[] trustedCertificates = new Certificate[1];
    // client's initial trust store
    public final List<Certificate> clientTrustStore;
    // client's initial empty trust store
    public final List<Certificate> clientEmptyTrustStore = new ArrayList<>();

    public SecureIntegrationTestHelper() {
        // create client credentials
        try {
            // Get point values
            byte[] publicX = Hex
                    .decodeHex("89c048261979208666f2bfb188be1968fc9021c416ce12828c06f4e314c167b5".toCharArray());
            byte[] publicY = Hex
                    .decodeHex("cbf1eb7587f08e01688d9ada4be859137ca49f79394bad9179326b3090967b68".toCharArray());
            byte[] privateS = Hex
                    .decodeHex("e67b68d2aaeb6550f19d98cade3ad62b39532e02e6b422e1f7ea189dabaea5d2".toCharArray());

            // Get Elliptic Curve Parameter spec for secp256r1
            AlgorithmParameters algoParameters = AlgorithmParameters.getInstance("EC");
            algoParameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec parameterSpec = algoParameters.getParameterSpec(ECParameterSpec.class);

            // Create key specs
            KeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(publicX), new BigInteger(publicY)),
                    parameterSpec);
            KeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(privateS), parameterSpec);

            // Get keys
            clientPublicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
            clientPrivateKey = KeyFactory.getInstance("EC").generatePrivate(privateKeySpec);

            // Get certificates from key store
            char[] clientKeyStorePwd = "client".toCharArray();
            KeyStore clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream clientKeyStoreFile = new FileInputStream("./credentials/clientKeyStore.jks")) {
                clientKeyStore.load(clientKeyStoreFile, clientKeyStorePwd);
            }

            clientPrivateKeyFromCert = (PrivateKey) clientKeyStore.getKey("client", clientKeyStorePwd);
            clientX509Cert = (X509Certificate) clientKeyStore.getCertificate("client");
            clientX509CertWithBadCN = (X509Certificate) clientKeyStore.getCertificate("client_bad_cn");
            clientX509CertSelfSigned = (X509Certificate) clientKeyStore.getCertificate("client_self_signed");
            clientX509CertNotTrusted = (X509Certificate) clientKeyStore.getCertificate("client_not_trusted");

            mfgClientPrivateKeyFromCert = (PrivateKey) clientKeyStore.getKey("mfgClient", clientKeyStorePwd);
            mfgClientX509CertChain = X509Util.asX509Certificates(clientKeyStore.getCertificateChain("mfgClient"));
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }

        // create server credentials
        try {
            // Get point values
            byte[] publicX = Hex
                    .decodeHex("fcc28728c123b155be410fc1c0651da374fc6ebe7f96606e90d927d188894a73".toCharArray());
            byte[] publicY = Hex
                    .decodeHex("d2ffaa73957d76984633fc1cc54d0b763ca0559a9dff9706e9f4557dacc3f52a".toCharArray());
            byte[] privateS = Hex
                    .decodeHex("1dae121ba406802ef07c193c1ee4df91115aabd79c1ed7f4c0ef7ef6a5449400".toCharArray());

            // Get Elliptic Curve Parameter spec for secp256r1
            AlgorithmParameters algoParameters = AlgorithmParameters.getInstance("EC");
            algoParameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec parameterSpec = algoParameters.getParameterSpec(ECParameterSpec.class);

            // Create key specs
            KeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(publicX), new BigInteger(publicY)),
                    parameterSpec);
            KeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(privateS), parameterSpec);

            // Get keys
            serverPublicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
            serverPrivateKey = KeyFactory.getInstance("EC").generatePrivate(privateKeySpec);

            // Get certificates from key store
            char[] serverKeyStorePwd = "server".toCharArray();
            KeyStore serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream serverKeyStoreFile = new FileInputStream("./credentials/serverKeyStore.jks")) {
                serverKeyStore.load(serverKeyStoreFile, serverKeyStorePwd);
            }

            serverPrivateKeyFromCert = (PrivateKey) serverKeyStore.getKey("server", serverKeyStorePwd);
            serverIntPrivateKeyFromCert = (PrivateKey) serverKeyStore.getKey("serverint", serverKeyStorePwd);
            rootCAX509Cert = (X509Certificate) serverKeyStore.getCertificate("rootCA");
            serverX509Cert = (X509Certificate) serverKeyStore.getCertificate("server");
            serverX509CertSelfSigned = (X509Certificate) serverKeyStore.getCertificate("server_self_signed");
            serverIntX509CertSelfSigned = (X509Certificate) serverKeyStore.getCertificate("serverInt_self_signed");
            serverIntX509CertChain = X509Util.asX509Certificates(serverKeyStore.getCertificateChain("serverint"));
            trustedCertificates[0] = rootCAX509Cert;
            clientTrustStore = Arrays.asList(new Certificate[] { rootCAX509Cert });
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void createPSKClient() {
        createPSKClient(false);
    }

    public void createPSKClientUsingQueueMode() {
        createPSKClient(true);
    }

    public void createPSKClient(boolean queueMode) {
        ObjectsInitializer initializer = new TestObjectsInitializer();
        initializer.setInstancesForObject(LwM2mId.SECURITY,
                Security.psk(
                        "coaps://" + server.getSecuredAddress().getHostString() + ":"
                                + server.getSecuredAddress().getPort(),
                        12345, GOOD_PSK_ID.getBytes(StandardCharsets.UTF_8), GOOD_PSK_KEY));
        initializer.setInstancesForObject(LwM2mId.SERVER, new Server(12345, LIFETIME));
        initializer.setInstancesForObject(LwM2mId.DEVICE, new Device("Eclipse Leshan", MODEL_NUMBER, "12345"));
        initializer.setDummyInstancesForObject(LwM2mId.ACCESS_CONTROL);
        List<LwM2mObjectEnabler> objects = initializer.createAll();

        InetSocketAddress clientAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        LeshanClientBuilder builder = new LeshanClientBuilder(getCurrentEndpoint());
        builder.setRegistrationEngineFactory(new DefaultRegistrationEngineFactory().setQueueMode(queueMode));
        builder.setLocalAddress(clientAddress.getHostString(), clientAddress.getPort());
        builder.setObjects(objects);
        builder.setDtlsConfig(
                new DtlsConnectorConfig.Builder().setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));

        // set an editable PSK store for tests
        builder.setEndpointFactory(new EndpointFactory() {

            @Override
            public CoapEndpoint createUnsecuredEndpoint(InetSocketAddress address, NetworkConfig coapConfig,
                    ObservationStore store) {
                CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
                builder.setInetSocketAddress(address);
                builder.setNetworkConfig(coapConfig);
                return builder.build();
            }

            @Override
            public CoapEndpoint createSecuredEndpoint(DtlsConnectorConfig dtlsConfig, NetworkConfig coapConfig,
                    ObservationStore store) {
                CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
                Builder dtlsConfigBuilder = new Builder(dtlsConfig);

                // tricks to be able to change psk information on the fly
                AdvancedPskStore pskStore = dtlsConfig.getAdvancedPskStore();
                if (pskStore != null) {
                    PskPublicInformation identity = pskStore.getIdentity(null, null);
                    SecretKey key = pskStore
                            .requestPskSecretResult(ConnectionId.EMPTY, null, identity, null, null, null, false).getSecret();
                    singlePSKStore = new SinglePSKStore(identity, key);
                    dtlsConfigBuilder.setAdvancedPskStore(singlePSKStore);
                }
                builder.setConnector(new DTLSConnector(dtlsConfigBuilder.build()));
                builder.setNetworkConfig(coapConfig);
                return builder.build();
            }
        });

        // create client;
        client = builder.build();
        setupClientMonitoring();
    }

    public void setNewPsk(String identity, byte[] key) {
        if (identity != null)
            singlePSKStore.setIdentity(identity);
        if (key != null)
            singlePSKStore.setKey(key);
    }

    public void createRPKClient(boolean useServerCertificate) {
        ObjectsInitializer initializer = new TestObjectsInitializer();
        initializer.setInstancesForObject(LwM2mId.SECURITY, Security.rpk(
                "coaps://" + server.getSecuredAddress().getHostString() + ":" + server.getSecuredAddress().getPort(),
                12345, clientPublicKey.getEncoded(), clientPrivateKey.getEncoded(),
                useServerCertificate ? serverX509Cert.getPublicKey().getEncoded() : serverPublicKey.getEncoded()));
        initializer.setInstancesForObject(LwM2mId.SERVER, new Server(12345, LIFETIME));
        initializer.setInstancesForObject(LwM2mId.DEVICE, new Device("Eclipse Leshan", MODEL_NUMBER, "12345"));
        initializer.setClassForObject(LwM2mId.ACCESS_CONTROL, DummyInstanceEnabler.class);
        List<LwM2mObjectEnabler> objects = initializer.createAll();

        InetSocketAddress clientAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        LeshanClientBuilder builder = new LeshanClientBuilder(getCurrentEndpoint());
        builder.setLocalAddress(clientAddress.getHostString(), clientAddress.getPort());
        builder.setObjects(objects);
        client = builder.build();
        setupClientMonitoring();
    }

    public void createRPKClient() {
        createRPKClient(false);
    }

    public void setEndpointNameFromX509(X509Certificate certificate) {
        X500Principal subjectDN = certificate.getSubjectX500Principal();
        String endpointName = X509CertUtil.getPrincipalField(subjectDN, "CN");
        setCurrentEndpoint(endpointName);
    }

    public void createX509CertClient() throws CertificateEncodingException {
        createX509CertClient(clientX509Cert, clientPrivateKeyFromCert, serverX509Cert);
    }

    public void createX509CertClient(Certificate clientCertificate) throws CertificateEncodingException {
        createX509CertClient(clientCertificate, clientPrivateKeyFromCert, serverX509Cert);
    }

    public void createX509CertClient(Certificate clientCertificate, PrivateKey privatekey)
            throws CertificateEncodingException {
        createX509CertClient(clientCertificate, privatekey, serverX509Cert);
    }

    public void createX509CertClient(Certificate clientCertificate, PrivateKey privatekey,
            Certificate serverCertificate) throws CertificateEncodingException {
        ObjectsInitializer initializer = new TestObjectsInitializer();
        initializer.setInstancesForObject(LwM2mId.SECURITY,
                Security.x509(
                        "coaps://" + server.getSecuredAddress().getHostString() + ":"
                                + server.getSecuredAddress().getPort(),
                        12345, clientCertificate.getEncoded(), privatekey.getEncoded(),
                        serverCertificate.getEncoded()));
        initializer.setInstancesForObject(LwM2mId.SERVER, new Server(12345, LIFETIME));
        initializer.setInstancesForObject(LwM2mId.DEVICE, new Device("Eclipse Leshan", MODEL_NUMBER, "12345"));
        initializer.setClassForObject(LwM2mId.ACCESS_CONTROL, DummyInstanceEnabler.class);
        List<LwM2mObjectEnabler> objects = initializer.createAll();

        InetSocketAddress clientAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        LeshanClientBuilder builder = new LeshanClientBuilder(getCurrentEndpoint());
        builder.setLocalAddress(clientAddress.getHostString(), clientAddress.getPort());

        Builder dtlsConfig = new DtlsConnectorConfig.Builder();
        builder.setDtlsConfig(dtlsConfig);

        builder.setObjects(objects);
        client = builder.build();
        setupClientMonitoring();
    }

    public void createX509CertClient(X509Certificate[] clientCertificate, PrivateKey privatekey,
            List<Certificate> clientTrustStore, X509Certificate serverCertificate, CertificateUsage certificateUsage)
            throws CertificateEncodingException {
        /* Make sure there is only 1 certificate in chain before client certificate chains are supported */
        assert (clientCertificate.length == 1);

        ObjectsInitializer initializer = new TestObjectsInitializer();
        initializer.setInstancesForObject(LwM2mId.SECURITY,
                Security.x509(
                        "coaps://" + server.getSecuredAddress().getHostString() + ":"
                                + server.getSecuredAddress().getPort(),
                        12345, clientCertificate[0].getEncoded(), privatekey.getEncoded(),
                        serverCertificate.getEncoded(), certificateUsage.code));
        initializer.setInstancesForObject(LwM2mId.SERVER, new Server(12345, LIFETIME));
        initializer.setInstancesForObject(LwM2mId.DEVICE, new Device("Eclipse Leshan", MODEL_NUMBER, "12345"));
        initializer.setClassForObject(LwM2mId.ACCESS_CONTROL, DummyInstanceEnabler.class);
        List<LwM2mObjectEnabler> objects = initializer.createAll();

        InetSocketAddress clientAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        LeshanClientBuilder builder = new LeshanClientBuilder(getCurrentEndpoint());
        builder.setLocalAddress(clientAddress.getHostString(), clientAddress.getPort());
        builder.setTrustStore(clientTrustStore);

        Builder dtlsConfig = new DtlsConnectorConfig.Builder();
        builder.setDtlsConfig(dtlsConfig);

        builder.setObjects(objects);
        client = builder.build();
        setupClientMonitoring();
    }

    @Override
    protected LeshanServerBuilder createServerBuilder() {
        return createServerBuilder(null);
    }

    @Override
    protected SecurityStore createSecurityStore() {
        securityStore = new InMemorySecurityStore();
        return securityStore;
    }

    protected LeshanServerBuilder createServerBuilder(Boolean serverOnly) {
        LeshanServerBuilder builder = super.createServerBuilder();
        Builder dtlsConfig = new DtlsConnectorConfig.Builder();
        dtlsConfig.setMaxRetransmissions(1);
        dtlsConfig.setRetransmissionTimeout(300);
        if (serverOnly != null) {
            dtlsConfig.setServerOnly(serverOnly);
        }
        builder.setDtlsConfig(dtlsConfig);
        return builder;
    }

    public void createServerWithRPK() {
        LeshanServerBuilder builder = createServerBuilder();
        builder.setPublicKey(serverPublicKey);
        builder.setPrivateKey(serverPrivateKey);

        server = builder.build();
        // monitor client registration
        setupServerMonitoring();
    }

    public void createServerWithX509Cert() {
        createServerWithX509Cert(serverX509Cert, serverPrivateKeyFromCert, true);
    }

    public void createServerWithX509Cert(X509Certificate serverCertificate, PrivateKey privateKey, Boolean serverOnly) {
        createServerWithX509Cert(new X509Certificate[] { serverCertificate }, privateKey, serverOnly);
    }

    public void createServerWithX509Cert(X509Certificate serverCertificateChain[], PrivateKey privateKey,
            Boolean serverOnly) {
        createServerWithX509Cert(serverCertificateChain, privateKey, this.trustedCertificates, serverOnly);
    }

    public void createServerWithX509Cert(X509Certificate serverCertificateChain[], PrivateKey privateKey,
            Certificate[] trustedCertificates, Boolean serverOnly) {
        LeshanServerBuilder builder = createServerBuilder(serverOnly);
        builder.setPrivateKey(privateKey);
        builder.setCertificateChain(serverCertificateChain);
        builder.setTrustedCertificates(trustedCertificates);
        builder.setAuthorizer(new DefaultAuthorizer(securityStore, new SecurityChecker() {
            @Override
            protected boolean matchX509Identity(String endpoint, String receivedX509CommonName,
                    String expectedX509CommonName) {
                return expectedX509CommonName.equals(receivedX509CommonName);
            }
        }));

        server = builder.build();
        // monitor client registration
        setupServerMonitoring();
    }

    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }

    public EditableSecurityStore getSecurityStore() {
        return (EditableSecurityStore) server.getSecurityStore();
    }

    @Override
    public void dispose() {
        getSecurityStore().remove(getCurrentEndpoint(), false);
        getSecurityStore().remove(BAD_ENDPOINT, false);
        getSecurityStore().remove(GOOD_ENDPOINT, false);
        super.dispose();
    }
}
