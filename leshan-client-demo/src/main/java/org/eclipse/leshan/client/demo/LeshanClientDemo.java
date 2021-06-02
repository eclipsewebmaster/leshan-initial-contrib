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
 *     Sierra Wireless, - initial API and implementation
 *     Bosch Software Innovations GmbH, - initial API and implementation
 *******************************************************************************/

package org.eclipse.leshan.client.demo;

import static org.eclipse.leshan.client.object.Security.*;
import static org.eclipse.leshan.core.LwM2mId.*;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Option.Builder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.DTLSContext;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.SessionAdapter;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.leshan.client.californium.LeshanClient;
import org.eclipse.leshan.client.californium.LeshanClientBuilder;
import org.eclipse.leshan.client.engine.DefaultRegistrationEngineFactory;
import org.eclipse.leshan.client.object.Server;
import org.eclipse.leshan.client.resource.LwM2mObjectEnabler;
import org.eclipse.leshan.client.resource.ObjectsInitializer;
import org.eclipse.leshan.client.resource.listener.ObjectsListenerAdapter;
import org.eclipse.leshan.core.CertificateUsage;
import org.eclipse.leshan.core.LwM2m;
import org.eclipse.leshan.core.californium.DefaultEndpointFactory;
import org.eclipse.leshan.core.model.LwM2mModel;
import org.eclipse.leshan.core.model.ObjectLoader;
import org.eclipse.leshan.core.model.ObjectModel;
import org.eclipse.leshan.core.model.ResourceModel;
import org.eclipse.leshan.core.model.ResourceModel.Operations;
import org.eclipse.leshan.core.model.ResourceModel.Type;
import org.eclipse.leshan.core.model.StaticModel;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mDecoder;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mEncoder;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.core.util.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LeshanClientDemo {

    private static final Logger LOG = LoggerFactory.getLogger(LeshanClientDemo.class);

    // /!\ This field is a COPY of org.eclipse.leshan.server.demo.LeshanServerDemo.modelPaths /!\
    // TODO create a leshan-demo project ?
    public final static String[] modelPaths = new String[] { "8.xml", "9.xml", "10.xml", "11.xml", "12.xml", "13.xml",
                            "14.xml", "15.xml", "16.xml", "19.xml", "20.xml", "22.xml", "500.xml", "501.xml", "502.xml",
                            "503.xml", "2048.xml", "2049.xml", "2050.xml", "2051.xml", "2052.xml", "2053.xml",
                            "2054.xml", "2055.xml", "2056.xml", "2057.xml", "3200.xml", "3201.xml", "3202.xml",
                            "3203.xml", "3300.xml", "3301.xml", "3302.xml", "3303.xml", "3304.xml", "3305.xml",
                            "3306.xml", "3308.xml", "3310.xml", "3311.xml", "3312.xml", "3313.xml", "3314.xml",
                            "3315.xml", "3316.xml", "3317.xml", "3318.xml", "3319.xml", "3320.xml", "3321.xml",
                            "3322.xml", "3323.xml", "3324.xml", "3325.xml", "3326.xml", "3327.xml", "3328.xml",
                            "3329.xml", "3330.xml", "3331.xml", "3332.xml", "3333.xml", "3334.xml", "3335.xml",
                            "3336.xml", "3337.xml", "3338.xml", "3339.xml", "3340.xml", "3341.xml", "3342.xml",
                            "3343.xml", "3344.xml", "3345.xml", "3346.xml", "3347.xml", "3348.xml", "3349.xml",
                            "3350.xml", "3351.xml", "3352.xml", "3353.xml", "3354.xml", "3355.xml", "3356.xml",
                            "3357.xml", "3358.xml", "3359.xml", "3360.xml", "3361.xml", "3362.xml", "3363.xml",
                            "3364.xml", "3365.xml", "3366.xml", "3367.xml", "3368.xml", "3369.xml", "3370.xml",
                            "3371.xml", "3372.xml", "3373.xml", "3374.xml", "3375.xml", "3376.xml", "3377.xml",
                            "3378.xml", "3379.xml", "3380.xml", "3381.xml", "3382.xml", "3383.xml", "3384.xml",
                            "3385.xml", "3386.xml", "3387.xml", "3388.xml", "3389.xml", "3390.xml", "3391.xml",
                            "3392.xml", "3393.xml", "3394.xml", "3395.xml", "3396.xml", "3397.xml", "3398.xml",
                            "3399.xml", "3400.xml", "3401.xml", "3402.xml", "3403.xml", "3404.xml", "3405.xml",
                            "3406.xml", "3407.xml", "3408.xml", "3410.xml", "3411.xml", "3412.xml", "3413.xml",
                            "3414.xml", "3415.xml", "3416.xml", "3417.xml", "3418.xml", "3419.xml", "3420.xml",
                            "3421.xml", "3423.xml", "3424.xml", "3425.xml", "3426.xml", "3427.xml", "3428.xml",
                            "3429.xml", "3430.xml", "3431.xml", "3432.xml", "3433.xml", "3434.xml", "3435.xml",
                            "3436.xml", "3437.xml", "3438.xml", "3439.xml", "10241.xml", "10242.xml", "10243.xml",
                            "10244.xml", "10245.xml", "10246.xml", "10247.xml", "10248.xml", "10249.xml", "10250.xml",
                            "10251.xml", "10252.xml", "10253.xml", "10254.xml", "10255.xml", "10256.xml", "10257.xml",
                            "10258.xml", "10259.xml", "10260.xml", "10262.xml", "10263.xml", "10264.xml", "10265.xml",
                            "10266.xml", "10267.xml", "10268.xml", "10269.xml", "10270.xml", "10271.xml", "10272.xml",
                            "10273.xml", "10274.xml", "10275.xml", "10276.xml", "10277.xml", "10278.xml", "10279.xml",
                            "10280.xml", "10281.xml", "10282.xml", "10283.xml", "10284.xml", "10286.xml", "10290.xml",
                            "10291.xml", "10292.xml", "10299.xml", "10300.xml", "10308.xml", "10309.xml", "10311.xml",
                            "10313.xml", "10314.xml", "10315.xml", "10316.xml", "10318.xml", "10319.xml", "10320.xml",
                            "10322.xml", "10323.xml", "10324.xml", "10326.xml", "10327.xml", "10328.xml", "10329.xml",
                            "10330.xml", "10331.xml", "10332.xml", "10333.xml", "10334.xml", "10335.xml", "10336.xml",
                            "10337.xml", "10338.xml", "10339.xml", "10340.xml", "10341.xml", "10342.xml", "10343.xml",
                            "10344.xml", "10345.xml", "10346.xml", "10347.xml", "10348.xml", "10349.xml", "10350.xml",
                            "10351.xml", "10352.xml", "10353.xml", "10354.xml", "10355.xml", "10356.xml", "10357.xml",
                            "10358.xml", "10359.xml", "10360.xml", "10361.xml", "10362.xml", "10363.xml", "10364.xml",
                            "10365.xml", "10366.xml", "10368.xml", "10369.xml", "10371.xml", "18830.xml",
                            "18831.xml", };

    private static final int OBJECT_ID_TEMPERATURE_SENSOR = 3303;
    private final static String DEFAULT_ENDPOINT = "LeshanClientDemo";
    private final static int DEFAULT_LIFETIME = 5 * 60; // 5min in seconds
    private final static String USAGE = "java -jar leshan-client-demo.jar [OPTION]\n\n";

    private static MyLocation locationInstance;

    public static void main(final String[] args) {

        // Define options for command line tools
        Options options = new Options();

        final StringBuilder PSKChapter = new StringBuilder();
        PSKChapter.append("\n .");
        PSKChapter.append("\n .");
        PSKChapter.append("\n ================================[ PSK ]=================================");
        PSKChapter.append("\n | By default Leshan demo use non secure connection.                    |");
        PSKChapter.append("\n | To use PSK, -i and -p options should be used together.               |");
        PSKChapter.append("\n ------------------------------------------------------------------------");

        final StringBuilder RPKChapter = new StringBuilder();
        RPKChapter.append("\n .");
        RPKChapter.append("\n .");
        RPKChapter.append("\n ================================[ RPK ]=================================");
        RPKChapter.append("\n | By default Leshan demo use non secure connection.                    |");
        RPKChapter.append("\n | To use RPK, -cpubk -cprik -spubk options should be used together.    |");
        RPKChapter.append("\n | To get helps about files format and how to generate it, see :        |");
        RPKChapter.append("\n | See https://github.com/eclipse/leshan/wiki/Credential-files-format   |");
        RPKChapter.append("\n ------------------------------------------------------------------------");

        final StringBuilder X509Chapter = new StringBuilder();
        X509Chapter.append("\n .");
        X509Chapter.append("\n .");
        X509Chapter.append("\n ================================[X509]==================================");
        X509Chapter.append("\n | By default Leshan demo use non secure connection.                    |");
        X509Chapter.append("\n | To use X509, -ccert -cprik -scert options should be used together.   |");
        X509Chapter.append("\n | To get helps about files format and how to generate it, see :        |");
        X509Chapter.append("\n | See https://github.com/eclipse/leshan/wiki/Credential-files-format   |");
        X509Chapter.append("\n ------------------------------------------------------------------------");

        options.addOption("h", "help", false, "Display help information.");
        options.addOption("n", true, String.format(
                "Set the endpoint name of the Client.\nDefault: the local hostname or '%s' if any.", DEFAULT_ENDPOINT));
        options.addOption("b", false, "If present use bootstrap.");
        options.addOption("l", true, String.format(
                "The lifetime in seconds used to register, ignored if -b is used.\n Default : %ds", DEFAULT_LIFETIME));
        options.addOption("cp", true,
                "The communication period in seconds which should be smaller than the lifetime, will be used even if -b is used.");
        options.addOption("lh", true, "Set the local CoAP address of the Client.\n  Default: any local address.");
        options.addOption("lp", true,
                "Set the local CoAP port of the Client.\n  Default: A valid port value is between 0 and 65535.");
        options.addOption("u", true, String.format("Set the LWM2M or Bootstrap server URL.\nDefault: localhost:%d.",
                LwM2m.DEFAULT_COAP_PORT));
        options.addOption("r", false, "Force reconnect/rehandshake on update.");
        options.addOption("f", false, "Do not try to resume session always, do a full handshake.");
        options.addOption("ocf",
                "activate support of old/unofficial content format .\n See https://github.com/eclipse/leshan/pull/720");
        Builder c = Option.builder("c");
        c.desc("define cipher suites used.");
        c.hasArgs();
        options.addOption(c.build());
        options.addOption("oc", "activate support of old/deprecated cipher suites.");
        options.addOption("cid", true, "Control usage of DTLS connection ID." //
                + "\n - 'on' to activate Connection ID support (same as -cid 0)" //
                + "\n - 'off' to deactivate it" //
                + "\n - Positive value define the size in byte of CID generated."
                + "\n - 0 value means we accept to use CID but will not generated one for foreign peer."
                + "\n (Default: off)");

        Builder aa = Option.builder("aa");
        aa.desc("Use additional attributes at registration time, syntax is \n -aa attrName1=attrValue1 attrName2=\\\"attrValue2\\\" ...");
        aa.hasArgs();
        options.addOption(aa.build());
        Builder bsaa = Option.builder("bsaa");
        bsaa.desc(
                "Use additional attributes at bootstrap time, syntax is \n -bsaa attrName1=attrValue1 attrName2=\\\"attrValue2\\\" ...");
        bsaa.hasArgs();
        options.addOption(bsaa.build());
        options.addOption("m", true, "A folder which contains object models in OMA DDF(.xml)format.");
        options.addOption("pos", true,
                "Set the initial location (latitude, longitude) of the device to be reported by the Location object.\n Format: lat_float:long_float");
        options.addOption("sf", true, "Scale factor to apply when shifting position.\n Default is 1.0." + PSKChapter);
        options.addOption("i", true, "Set the LWM2M or Bootstrap server PSK identity in ascii.");
        options.addOption("p", true, "Set the LWM2M or Bootstrap server Pre-Shared-Key in hexa." + RPKChapter);
        options.addOption("cpubk", true,
                "The path to your client public key file.\n The public Key should be in SubjectPublicKeyInfo format (DER encoding).");
        options.addOption("cprik", true,
                "The path to your client private key file.\nThe private key should be in PKCS#8 format (DER encoding).");
        options.addOption("spubk", true,
                "The path to your server public key file.\n The public Key should be in SubjectPublicKeyInfo format (DER encoding)."
                        + X509Chapter);
        options.addOption("ccert", true,
                "The path to your client certificate file.\n The certificate Common Name (CN) should generaly be equal to the client endpoint name (see -n option).\nThe certificate should be in X509v3 format (DER encoding).");
        options.addOption("scert", true,
                "The path to your server certificate file (see -certificate-usage option).\n The certificate should be in X509v3 format (DER encoding).");

        final StringBuilder trustStoreChapter = new StringBuilder();
        trustStoreChapter.append("\n .");
        trustStoreChapter
                .append("\n URI format: file://<path-to-trust-store-file>#<hex-strore-password>#<alias-pattern>");
        trustStoreChapter.append("\n .");
        trustStoreChapter.append("\n Where:");
        trustStoreChapter.append("\n - path-to-trust-store-file is path to pkcs12 trust store file");
        trustStoreChapter.append("\n - hex-store-password is HEX formatted password for store");
        trustStoreChapter.append(
                "\n - alias-pattern can be used to filter trusted certificates and can also be empty to get all");
        trustStoreChapter.append("\n .");
        trustStoreChapter.append("\n Default: empty store.");

        options.addOption("truststore", true,
                "The path to a root certificate file to trust or a folder containing all the trusted certificates in X509v3 format (DER encoding) or trust store URI."
                        + trustStoreChapter);

        final StringBuilder certUsageChapter = new StringBuilder();
        certUsageChapter.append("\n - 0 : CA constraint");
        certUsageChapter.append("\n - 1 : service certificate constraint");
        certUsageChapter.append("\n - 2 : trust anchor assertion");
        certUsageChapter.append("\n - 3 : domain issued certificate (Default value)");
        certUsageChapter.append("\n (Usage are described at https://tools.ietf.org/html/rfc6698#section-2.1.1)");

        options.addOption("cu", "certificate-usage", true,
                "Certificate Usage (as integer) defining how to use server certificate." + certUsageChapter);

        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(120);
        formatter.setOptionComparator(null);

        // Parse arguments
        CommandLine cl;
        try {
            cl = new DefaultParser().parse(options, args);
        } catch (ParseException e) {
            System.err.println("Parsing failed.  Reason: " + e.getMessage());
            formatter.printHelp(USAGE, options);
            return;
        }

        // Print help
        if (cl.hasOption("help")) {
            formatter.printHelp(USAGE, options);
            return;
        }

        // Abort if unexpected options
        if (cl.getArgs().length > 0) {
            System.err.println("Unexpected option or arguments : " + cl.getArgList());
            formatter.printHelp(USAGE, options);
            return;
        }

        // Abort if PSK config is not complete
        if ((cl.hasOption("i") && !cl.hasOption("p")) || !cl.hasOption("i") && cl.hasOption("p")) {
            System.err
                    .println("You should precise identity (-i) and Pre-Shared-Key (-p) if you want to connect in PSK");
            formatter.printHelp(USAGE, options);
            return;
        }

        // Abort if all RPK config is not complete
        boolean rpkConfig = false;
        if (cl.hasOption("cpubk") || cl.hasOption("spubk")) {
            if (!cl.hasOption("cpubk") || !cl.hasOption("cprik") || !cl.hasOption("spubk")) {
                System.err.println("cpubk, cprik and spubk should be used together to connect using RPK");
                formatter.printHelp(USAGE, options);
                return;
            } else {
                rpkConfig = true;
            }
        }

        // Abort if all X509 config is not complete
        boolean x509config = false;
        if (cl.hasOption("ccert") || cl.hasOption("scert")) {
            if (!cl.hasOption("ccert") || !cl.hasOption("cprik") || !cl.hasOption("scert")) {
                System.err.println("ccert, cprik and scert should be used together to connect using X509");
                formatter.printHelp(USAGE, options);
                return;
            } else {
                x509config = true;
            }
        }

        // Abort if cprik is used without complete RPK or X509 config
        if (cl.hasOption("cprik")) {
            if (!x509config && !rpkConfig) {
                System.err.println(
                        "cprik should be used with ccert and scert for X509 config OR cpubk and spubk for RPK config");
                formatter.printHelp(USAGE, options);
                return;
            }
        }

        // Abort if cu is used without complete X509 config
        if (cl.hasOption("cu")) {
            if (!x509config) {
                System.err.println("cu should be used with ccert and scert for X509 config.");
                formatter.printHelp(USAGE, options);
                return;
            }
        }

        // Get endpoint name
        String endpoint;
        if (cl.hasOption("n")) {
            endpoint = cl.getOptionValue("n");
        } else {
            try {
                endpoint = InetAddress.getLocalHost().getHostName();
            } catch (UnknownHostException e) {
                endpoint = DEFAULT_ENDPOINT;
            }
        }

        // Get lifetime
        int lifetime;
        if (cl.hasOption("l")) {
            lifetime = Integer.parseInt(cl.getOptionValue("l"));
        } else {
            lifetime = DEFAULT_LIFETIME;
        }

        // Get lifetime
        Integer communicationPeriod = null;
        if (cl.hasOption("cp")) {
            communicationPeriod = Integer.valueOf(cl.getOptionValue("cp")) * 1000;
        }

        // Get additional attributes for registration
        Map<String, String> additionalAttributes = null;
        if (cl.hasOption("aa")) {
            additionalAttributes = new HashMap<>();
            Pattern p1 = Pattern.compile("(.*)=\"(.*)\"");
            Pattern p2 = Pattern.compile("(.*)=(.*)");
            String[] values = cl.getOptionValues("aa");
            for (String v : values) {
                Matcher m = p1.matcher(v);
                if (m.matches()) {
                    String attrName = m.group(1);
                    String attrValue = m.group(2);
                    additionalAttributes.put(attrName, attrValue);
                } else {
                    m = p2.matcher(v);
                    if (m.matches()) {
                        String attrName = m.group(1);
                        String attrValue = m.group(2);
                        additionalAttributes.put(attrName, attrValue);
                    } else {
                        System.err.println(String.format("Invalid syntax for additional attributes : %s", v));
                        return;
                    }
                }
            }
        }

        // Get additional attributes for bootstrap
        Map<String, String> bsAdditionalAttributes = null;
        if (cl.hasOption("bsaa")) {
            bsAdditionalAttributes = new HashMap<>();
            Pattern p1 = Pattern.compile("(.*)=\"(.*)\"");
            Pattern p2 = Pattern.compile("(.*)=(.*)");
            String[] values = cl.getOptionValues("bsaa");
            for (String v : values) {
                Matcher m = p1.matcher(v);
                if (m.matches()) {
                    String attrName = m.group(1);
                    String attrValue = m.group(2);
                    bsAdditionalAttributes.put(attrName, attrValue);
                } else {
                    m = p2.matcher(v);
                    if (m.matches()) {
                        String attrName = m.group(1);
                        String attrValue = m.group(2);
                        bsAdditionalAttributes.put(attrName, attrValue);
                    } else {
                        System.err.println(String.format("Invalid syntax for additional attributes : %s", v));
                        return;
                    }
                }
            }
        }

        // Get server URI
        String serverURI;
        if (cl.hasOption("u")) {
            if (cl.hasOption("i") || cl.hasOption("cpubk") || cl.hasOption("ccert"))
                serverURI = "coaps://" + cl.getOptionValue("u");
            else
                serverURI = "coap://" + cl.getOptionValue("u");
        } else {
            if (cl.hasOption("i") || cl.hasOption("cpubk") || cl.hasOption("ccert"))
                serverURI = "coaps://localhost:" + LwM2m.DEFAULT_COAP_SECURE_PORT;
            else
                serverURI = "coap://localhost:" + LwM2m.DEFAULT_COAP_PORT;
        }

        // Get CID config
        String cidOption = cl.getOptionValue("cid");
        Integer cid = null;
        if (cidOption != null) {
            if ("off".equals(cidOption)) {
                cid = null;
            } else if ("on".equals(cidOption)) {
                cid = 0;
            } else {
                cid = Integer.parseInt(cidOption);
                cid = cid < 0 ? null : cid;
            }
        }

        // get PSK info
        byte[] pskIdentity = null;
        byte[] pskKey = null;
        if (cl.hasOption("i")) {
            pskIdentity = cl.getOptionValue("i").getBytes();
            pskKey = Hex.decodeHex(cl.getOptionValue("p").toCharArray());
        }

        // get RPK info
        PublicKey clientPublicKey = null;
        PrivateKey clientPrivateKey = null;
        PublicKey serverPublicKey = null;
        if (cl.hasOption("cpubk")) {
            try {
                clientPrivateKey = SecurityUtil.privateKey.readFromFile(cl.getOptionValue("cprik"));
                clientPublicKey = SecurityUtil.publicKey.readFromFile(cl.getOptionValue("cpubk"));
                serverPublicKey = SecurityUtil.publicKey.readFromFile(cl.getOptionValue("spubk"));
            } catch (Exception e) {
                System.err.println("Unable to load RPK files : " + e.getMessage());
                e.printStackTrace();
                formatter.printHelp(USAGE, options);
                return;
            }
        }

        // get X509 info
        X509Certificate clientCertificate = null;
        X509Certificate serverCertificate = null;
        if (cl.hasOption("ccert")) {
            try {
                clientPrivateKey = SecurityUtil.privateKey.readFromFile(cl.getOptionValue("cprik"));
                clientCertificate = SecurityUtil.certificate.readFromFile(cl.getOptionValue("ccert"));
                serverCertificate = SecurityUtil.certificate.readFromFile(cl.getOptionValue("scert"));
            } catch (Exception e) {
                System.err.println("Unable to load X509 files : " + e.getMessage());
                e.printStackTrace();
                formatter.printHelp(USAGE, options);
                return;
            }
        }

        List<CipherSuite> ciphers = null;
        if (cl.hasOption("c")) {
            ciphers = new ArrayList<>();
            String[] values = cl.getOptionValues("c");
            boolean wasIgnore = false;
            for (String v : values) {
                try {
                    ciphers.add(CipherSuite.valueOf(v));
                } catch (IllegalArgumentException e) {
                    LOG.warn("unknown cipher suite from '-c' option : {}", v);
                    wasIgnore = true;
                }
            }
            if (wasIgnore) {
                StringBuilder supportedCiphers = new StringBuilder();
                for (CipherSuite supportedCipher : EnumSet.allOf(CipherSuite.class)) {
                    supportedCiphers.append(System.lineSeparator());
                    supportedCiphers.append("  ");
                    supportedCiphers.append(supportedCipher);
                }
                LOG.warn("Potentially supported cipher suites are : {}", supportedCiphers);
            }
            if (ciphers.isEmpty()) {
                LOG.warn("All cipher are ignored, default ones will be used");
                ciphers = null;
            }
        }

        // configure trust store if given
        List<Certificate> trustStore = Collections.emptyList();
        if (cl.hasOption("truststore")) {
            trustStore = new ArrayList<>();

            String trustStoreName = cl.getOptionValue("truststore");

            if (trustStoreName.startsWith("file://")) {
                // Treat argument as Java trust store
                try {
                    Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(trustStoreName);
                    trustStore.addAll(Arrays.asList(trustedCertificates));
                } catch (Exception e) {
                    System.err.println("Failed to load trust store : " + e.getMessage());
                    e.printStackTrace();
                    formatter.printHelp(USAGE, options);
                    return;
                }
            } else {
                // Treat argument as file or directory
                File input = new File(cl.getOptionValue("truststore"));

                // check input exists
                if (!input.exists()) {
                    System.err.println(
                            "Failed to load trust store - file or directory does not exist : " + input.toString());
                    formatter.printHelp(USAGE, options);
                    return;
                }

                // get input files.
                File[] files;
                if (input.isDirectory()) {
                    files = input.listFiles();
                } else {
                    files = new File[] { input };
                }
                for (File file : files) {
                    try {
                        trustStore.add(SecurityUtil.certificate.readFromFile(file.getAbsolutePath()));
                    } catch (Exception e) {
                        LOG.warn("Unable to load X509 files {} : {} ", file.getAbsolutePath(), e.getMessage());
                    }
                }
            }
        }

        CertificateUsage certificateUsage = CertificateUsage.DOMAIN_ISSUER_CERTIFICATE;
        if (cl.hasOption("cu")) {
            certificateUsage = CertificateUsage.fromCode(Integer.parseInt(cl.getOptionValue("cu")));
            if (trustStore.isEmpty()) {
                if (certificateUsage == CertificateUsage.SERVICE_CERTIFICATE_CONSTRAINT) {
                    System.err.println(
                            "You need to set a truststore when you are using \"service certificate constraint\" usage");
                    formatter.printHelp(USAGE, options);
                    return;
                }
            }
        }

        // get local address
        String localAddress = null;
        int localPort = 0;
        if (cl.hasOption("lh")) {
            localAddress = cl.getOptionValue("lh");
        }
        if (cl.hasOption("lp")) {
            localPort = Integer.parseInt(cl.getOptionValue("lp"));
        }

        Float latitude = null;
        Float longitude = null;
        Float scaleFactor = 1.0f;
        // get initial Location
        if (cl.hasOption("pos")) {
            try {
                String pos = cl.getOptionValue("pos");
                int colon = pos.indexOf(':');
                if (colon == -1 || colon == 0 || colon == pos.length() - 1) {
                    System.err.println("Position must be a set of two floats separated by a colon, e.g. 48.131:11.459");
                    formatter.printHelp(USAGE, options);
                    return;
                }
                latitude = Float.valueOf(pos.substring(0, colon));
                longitude = Float.valueOf(pos.substring(colon + 1));
            } catch (NumberFormatException e) {
                System.err.println("Position must be a set of two floats separated by a colon, e.g. 48.131:11.459");
                formatter.printHelp(USAGE, options);
                return;
            }
        }
        if (cl.hasOption("sf")) {
            try {
                scaleFactor = Float.valueOf(cl.getOptionValue("sf"));
            } catch (NumberFormatException e) {
                System.err.println("Scale factor must be a float, e.g. 1.0 or 0.01");
                formatter.printHelp(USAGE, options);
                return;
            }
        }

        // Get models folder
        String modelsFolderPath = cl.getOptionValue("m");

        try {
            createAndStartClient(endpoint, localAddress, localPort, cl.hasOption("b"), additionalAttributes,
                    bsAdditionalAttributes, lifetime, communicationPeriod, serverURI, pskIdentity, pskKey,
                    clientPrivateKey, clientPublicKey, serverPublicKey, clientCertificate, serverCertificate,
                    trustStore, certificateUsage, latitude, longitude, scaleFactor, cl.hasOption("ocf"),
                    cl.hasOption("oc"), cl.hasOption("r"), cl.hasOption("f"), modelsFolderPath, ciphers, cid);
        } catch (Exception e) {
            System.err.println("Unable to create and start client ...");
            e.printStackTrace();
            return;
        }
    }

    public static void createAndStartClient(String endpoint, String localAddress, int localPort, boolean needBootstrap,
            Map<String, String> additionalAttributes, Map<String, String> bsAdditionalAttributes, int lifetime,
            Integer communicationPeriod, String serverURI, byte[] pskIdentity, byte[] pskKey,
            PrivateKey clientPrivateKey, PublicKey clientPublicKey, PublicKey serverPublicKey,
            X509Certificate clientCertificate, X509Certificate serverCertificate, List<Certificate> trustStore,
            CertificateUsage certificateUsage, Float latitude, Float longitude, float scaleFactor,
            boolean supportOldFormat, boolean supportDeprecatedCiphers, boolean reconnectOnUpdate,
            boolean forceFullhandshake, String modelsFolderPath, List<CipherSuite> ciphers, Integer cid)
            throws Exception {

        locationInstance = new MyLocation(latitude, longitude, scaleFactor);

        // Initialize model
        List<ObjectModel> models = ObjectLoader.loadDefault();
        models.addAll(ObjectLoader.loadDdfResources("/models", modelPaths));
        if (modelsFolderPath != null) {
            models.addAll(ObjectLoader.loadObjectsFromDir(new File(modelsFolderPath), true));
        }

        Collection<ResourceModel> resources = Arrays
                .asList(new ResourceModel(1002, "string", Operations.RW, true, false, Type.STRING, null, null, null));
        ObjectModel objectModel = new ObjectModel(666, "test", "description", "1.0", false, false, resources, null,
                null, "description");
        models.add(objectModel);

        // Initialize object list
        final LwM2mModel model = new StaticModel(models);
        final ObjectsInitializer initializer = new ObjectsInitializer(model);
        if (needBootstrap) {
            if (pskIdentity != null) {
                initializer.setInstancesForObject(SECURITY, pskBootstrap(serverURI, pskIdentity, pskKey));
                initializer.setClassForObject(SERVER, Server.class);
            } else if (clientPublicKey != null) {
                initializer.setInstancesForObject(SECURITY, rpkBootstrap(serverURI, clientPublicKey.getEncoded(),
                        clientPrivateKey.getEncoded(), serverPublicKey.getEncoded()));
                initializer.setClassForObject(SERVER, Server.class);
            } else if (clientCertificate != null) {
                initializer.setInstancesForObject(SECURITY, x509Bootstrap(serverURI, clientCertificate.getEncoded(),
                        clientPrivateKey.getEncoded(), serverCertificate.getEncoded(), certificateUsage.code));
                initializer.setClassForObject(SERVER, Server.class);
            } else {
                initializer.setInstancesForObject(SECURITY, noSecBootstap(serverURI));
                initializer.setClassForObject(SERVER, Server.class);
            }
        } else {
            if (pskIdentity != null) {
                initializer.setInstancesForObject(SECURITY, psk(serverURI, 123, pskIdentity, pskKey));
                initializer.setInstancesForObject(SERVER, new Server(123, lifetime));
            } else if (clientPublicKey != null) {
                initializer.setInstancesForObject(SECURITY, rpk(serverURI, 123, clientPublicKey.getEncoded(),
                        clientPrivateKey.getEncoded(), serverPublicKey.getEncoded()));
                initializer.setInstancesForObject(SERVER, new Server(123, lifetime));
            } else if (clientCertificate != null) {
                initializer.setInstancesForObject(SECURITY, x509(serverURI, 123, clientCertificate.getEncoded(),
                        clientPrivateKey.getEncoded(), serverCertificate.getEncoded(), certificateUsage.code));
                initializer.setInstancesForObject(SERVER, new Server(123, lifetime));
            } else {
                initializer.setInstancesForObject(SECURITY, noSec(serverURI, 123));
                initializer.setInstancesForObject(SERVER, new Server(123, lifetime));
            }
        }
        initializer.setInstancesForObject(DEVICE, new MyDevice());
        initializer.setInstancesForObject(LOCATION, locationInstance);
        initializer.setInstancesForObject(OBJECT_ID_TEMPERATURE_SENSOR, new RandomTemperatureSensor());
        initializer.setInstancesForObject(666, new TestData());
        List<LwM2mObjectEnabler> enablers = initializer.createAll();

        // Create CoAP Config
        NetworkConfig coapConfig;
        File configFile = new File(NetworkConfig.DEFAULT_FILE_NAME);
        if (configFile.isFile()) {
            coapConfig = new NetworkConfig();
            coapConfig.load(configFile);
        } else {
            coapConfig = LeshanClientBuilder.createDefaultNetworkConfig();
            coapConfig.store(configFile);
        }

        // Create DTLS Config
        DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
        dtlsConfig.setRecommendedCipherSuitesOnly(!supportDeprecatedCiphers);
        if (ciphers != null) {
            dtlsConfig.setSupportedCipherSuites(ciphers);
        }
        if (cid != null) {
            dtlsConfig.setConnectionIdGenerator(new SingleNodeConnectionIdGenerator(cid));
        }

        // Configure Registration Engine
        DefaultRegistrationEngineFactory engineFactory = new DefaultRegistrationEngineFactory();
        engineFactory.setCommunicationPeriod(communicationPeriod);
        engineFactory.setReconnectOnUpdate(reconnectOnUpdate);
        engineFactory.setResumeOnConnect(!forceFullhandshake);

        // configure EndpointFactory
        DefaultEndpointFactory endpointFactory = new DefaultEndpointFactory("LWM2M CLIENT", true) {
            @Override
            protected Connector createSecuredConnector(DtlsConnectorConfig dtlsConfig) {

                return new DTLSConnector(dtlsConfig) {
                    @Override
                    protected void onInitializeHandshaker(Handshaker handshaker) {
                        handshaker.addSessionListener(new SessionAdapter() {

                            private SessionId sessionIdentifier = null;

                            @Override
                            public void handshakeStarted(Handshaker handshaker) throws HandshakeException {
                                if (handshaker instanceof ResumingServerHandshaker) {
                                    LOG.info("DTLS abbreviated Handshake initiated by server : STARTED ...");
                                } else if (handshaker instanceof ServerHandshaker) {
                                    LOG.info("DTLS Full Handshake initiated by server : STARTED ...");
                                } else if (handshaker instanceof ResumingClientHandshaker) {
                                    sessionIdentifier = handshaker.getSession().getSessionIdentifier();
                                    LOG.info("DTLS abbreviated Handshake initiated by client : STARTED ...");
                                } else if (handshaker instanceof ClientHandshaker) {
                                    LOG.info("DTLS Full Handshake initiated by client : STARTED ...");
                                }
                            }

                            @Override
                            public void contextEstablished(Handshaker handshaker, DTLSContext establishedContext)
                                    throws HandshakeException {
                                if (handshaker instanceof ResumingServerHandshaker) {
                                    LOG.info("DTLS abbreviated Handshake initiated by server : SUCCEED");
                                } else if (handshaker instanceof ServerHandshaker) {
                                    LOG.info("DTLS Full Handshake initiated by server : SUCCEED");
                                } else if (handshaker instanceof ResumingClientHandshaker) {
                                    if (sessionIdentifier != null && sessionIdentifier
                                            .equals(handshaker.getSession().getSessionIdentifier())) {
                                        LOG.info("DTLS abbreviated Handshake initiated by client : SUCCEED");
                                    } else {
                                        LOG.info(
                                                "DTLS abbreviated turns into Full Handshake initiated by client : SUCCEED");
                                    }
                                } else if (handshaker instanceof ClientHandshaker) {
                                    LOG.info("DTLS Full Handshake initiated by client : SUCCEED");
                                }
                            }

                            @Override
                            public void handshakeFailed(Handshaker handshaker, Throwable error) {
                                // get cause
                                String cause;
                                if (error != null) {
                                    if (error.getMessage() != null) {
                                        cause = error.getMessage();
                                    } else {
                                        cause = error.getClass().getName();
                                    }
                                } else {
                                    cause = "unknown cause";
                                }

                                if (handshaker instanceof ResumingServerHandshaker) {
                                    LOG.info("DTLS abbreviated Handshake initiated by server : FAILED ({})", cause);
                                } else if (handshaker instanceof ServerHandshaker) {
                                    LOG.info("DTLS Full Handshake initiated by server : FAILED ({})", cause);
                                } else if (handshaker instanceof ResumingClientHandshaker) {
                                    LOG.info("DTLS abbreviated Handshake initiated by client : FAILED ({})", cause);
                                } else if (handshaker instanceof ClientHandshaker) {
                                    LOG.info("DTLS Full Handshake initiated by client : FAILED ({})", cause);
                                }
                            }
                        });
                    }
                };
            }
        };

        // Create client
        LeshanClientBuilder builder = new LeshanClientBuilder(endpoint);
        builder.setLocalAddress(localAddress, localPort);
        builder.setObjects(enablers);
        builder.setCoapConfig(coapConfig);
        builder.setTrustStore(trustStore);
        builder.setDtlsConfig(dtlsConfig);
        builder.setRegistrationEngineFactory(engineFactory);
        builder.setEndpointFactory(endpointFactory);
        if (supportOldFormat) {
            builder.setDecoder(new DefaultLwM2mDecoder(true));
            builder.setEncoder(new DefaultLwM2mEncoder(true));
        }
        builder.setAdditionalAttributes(additionalAttributes);
        builder.setBootstrapAdditionalAttributes(bsAdditionalAttributes);
        final LeshanClient client = builder.build();

        client.getObjectTree().addListener(new ObjectsListenerAdapter() {
            @Override
            public void objectRemoved(LwM2mObjectEnabler object) {
                LOG.info("Object {} disabled.", object.getId());
            }

            @Override
            public void objectAdded(LwM2mObjectEnabler object) {
                LOG.info("Object {} enabled.", object.getId());
            }
        });

        // Display client public key to easily add it in demo servers.
        if (clientPublicKey != null) {
            PublicKey rawPublicKey = clientPublicKey;
            if (rawPublicKey instanceof ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey) rawPublicKey;
                // Get x coordinate
                byte[] x = ecPublicKey.getW().getAffineX().toByteArray();
                if (x[0] == 0)
                    x = Arrays.copyOfRange(x, 1, x.length);

                // Get Y coordinate
                byte[] y = ecPublicKey.getW().getAffineY().toByteArray();
                if (y[0] == 0)
                    y = Arrays.copyOfRange(y, 1, y.length);

                // Get Curves params
                String params = ecPublicKey.getParams().toString();

                LOG.info(
                        "Client uses RPK : \n Elliptic Curve parameters  : {} \n Public x coord : {} \n Public y coord : {} \n Public Key (Hex): {} \n Private Key (Hex): {}",
                        params, Hex.encodeHexString(x), Hex.encodeHexString(y),
                        Hex.encodeHexString(rawPublicKey.getEncoded()),
                        Hex.encodeHexString(clientPrivateKey.getEncoded()));

            } else {
                throw new IllegalStateException("Unsupported Public Key Format (only ECPublicKey supported).");
            }
        }
        // Display X509 credentials to easily at it in demo servers.
        if (clientCertificate != null) {
            LOG.info("Client uses X509 : \n X509 Certificate (Hex): {} \n Private Key (Hex): {}",
                    Hex.encodeHexString(clientCertificate.getEncoded()),
                    Hex.encodeHexString(clientPrivateKey.getEncoded()));
        }

        // Print commands help
        StringBuilder commandsHelp = new StringBuilder("Commands available :");
        commandsHelp.append(System.lineSeparator());
        commandsHelp.append(System.lineSeparator());
        commandsHelp.append("  - create <objectId> : to enable a new object.");
        commandsHelp.append(System.lineSeparator());
        commandsHelp.append("  - delete <objectId> : to disable a new object.");
        commandsHelp.append(System.lineSeparator());
        commandsHelp.append("  - update : to trigger a registration update.");
        commandsHelp.append(System.lineSeparator());
        commandsHelp.append("  - w : to move to North.");
        commandsHelp.append(System.lineSeparator());
        commandsHelp.append("  - a : to move to East.");
        commandsHelp.append(System.lineSeparator());
        commandsHelp.append("  - s : to move to South.");
        commandsHelp.append(System.lineSeparator());
        commandsHelp.append("  - d : to move to West.");
        commandsHelp.append(System.lineSeparator());
        LOG.info(commandsHelp.toString());

        // Start the client
        client.start();

        // De-register on shutdown and stop client.
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                client.destroy(true); // send de-registration request before destroy
            }
        });

        // Change the location through the Console
        try (Scanner scanner = new Scanner(System.in)) {
            List<Character> wasdCommands = Arrays.asList('w', 'a', 's', 'd');
            while (scanner.hasNext()) {
                String command = scanner.next();
                if (command.startsWith("create")) {
                    try {
                        int objectId = scanner.nextInt();
                        if (client.getObjectTree().getObjectEnabler(objectId) != null) {
                            LOG.info("Object {} already enabled.", objectId);
                        }
                        if (model.getObjectModel(objectId) == null) {
                            LOG.info("Unable to enable Object {} : there no model for this.", objectId);
                        } else {
                            ObjectsInitializer objectsInitializer = new ObjectsInitializer(model);
                            objectsInitializer.setDummyInstancesForObject(objectId);
                            LwM2mObjectEnabler object = objectsInitializer.create(objectId);
                            client.getObjectTree().addObjectEnabler(object);
                        }
                    } catch (Exception e) {
                        // skip last token
                        scanner.next();
                        LOG.info("Invalid syntax, <objectid> must be an integer : create <objectId>");
                    }
                } else if (command.startsWith("delete")) {
                    try {
                        int objectId = scanner.nextInt();
                        if (objectId == 0 || objectId == 0 || objectId == 3) {
                            LOG.info("Object {} can not be disabled.", objectId);
                        } else if (client.getObjectTree().getObjectEnabler(objectId) == null) {
                            LOG.info("Object {} is not enabled.", objectId);
                        } else {
                            client.getObjectTree().removeObjectEnabler(objectId);
                        }
                    } catch (Exception e) {
                        // skip last token
                        scanner.next();
                        LOG.info("\"Invalid syntax, <objectid> must be an integer : delete <objectId>");
                    }
                } else if (command.startsWith("update")) {
                    client.triggerRegistrationUpdate();
                } else if (command.length() == 1 && wasdCommands.contains(command.charAt(0))) {
                    locationInstance.moveLocation(command);
                } else {
                    LOG.info("Unknown command '{}'", command);
                }
            }
        }
    }
}
