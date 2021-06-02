/*******************************************************************************
 * Copyright (c) 2020 Sierra Wireless and others.
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
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.leshan.core.util.Validate;

/**
 * This class implements Certificate Usage (1) - Service Certificate Constraint
 *
 * From RFC 6698:
 * 
 * <pre>
 * 1 -- Certificate usage 1 is used to specify an end entity
 *       certificate, or the public key of such a certificate, that MUST be
 *       matched with the end entity certificate given by the server in
 *       TLS.  This certificate usage is sometimes referred to as "service
 *       certificate constraint" because it limits which end entity
 *       certificate can be used by a given service on a host.  The target
 *       certificate MUST pass PKIX certification path validation and MUST
 *       match the TLSA record.
 * </pre>
 * 
 * For details about Certificate Usage please see:
 * <a href="https://tools.ietf.org/html/rfc6698#section-2.1.1">rfc6698#section-2.1.1</a> - The Certificate Usage Field
 */
public class ServiceCertificateConstraintCertificateVerifier extends BaseCertificateVerifier {

    private final Certificate serviceCertificate;
    private final X509Certificate[] trustedCertificates;

    public ServiceCertificateConstraintCertificateVerifier(Certificate serviceCertificate,
            X509Certificate[] trustedCertificates) {
        Validate.notNull(serviceCertificate);
        Validate.notNull(trustedCertificates);
        Validate.notEmpty(trustedCertificates);
        this.serviceCertificate = serviceCertificate;
        this.trustedCertificates = trustedCertificates;
    }

    @Override
    public CertPath verifyCertificate(boolean clientUsage, CertificateMessage message, InetSocketAddress peerSocket)
            throws HandshakeException {
        CertPath messageChain = message.getCertificateChain();

        validateCertificateChainNotEmpty(messageChain);

        X509Certificate receivedServerCertificate = validateReceivedCertificateIsSupported(messageChain);

        // - must do PKIX validation with trustStore
        CertPath certPath;
        try {
            certPath = X509Util.applyPKIXValidation(messageChain, trustedCertificates);
        } catch (GeneralSecurityException e) {
            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
            throw new HandshakeException("Certificate chain could not be validated", alert, e);
        }

        // - target certificate must match what is provided certificate in server info
        if (!serviceCertificate.equals(receivedServerCertificate)) {
            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
            throw new HandshakeException("Certificate chain could not be validated", alert);
        }

        // - validate server name
        validateSubject(peerSocket, receivedServerCertificate);

        return certPath;
    }
}
