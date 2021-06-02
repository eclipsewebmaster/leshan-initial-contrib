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
 * This class implements Certificate Usage (3) - Domain Issuer Certificate
 *
 * From RFC 6698:
 * 
 * <pre>
 * 3 -- Certificate usage 3 is used to specify a certificate, or the
 *       public key of such a certificate, that MUST match the end entity
 *       certificate given by the server in TLS.  This certificate usage is
 *       sometimes referred to as "domain-issued certificate" because it
 *       allows for a domain name administrator to issue certificates for a
 *       domain without involving a third-party CA.  The target certificate
 *       MUST match the TLSA record.  The difference between certificate
 *       usage 1 and certificate usage 3 is that certificate usage 1
 *       requires that the certificate pass PKIX validation, but PKIX
 *       validation is not tested for certificate usage 3.
 * </pre>
 * 
 * For details about Certificate Usage please see:
 * <a href="https://tools.ietf.org/html/rfc6698#section-2.1.1">rfc6698#section-2.1.1</a> - The Certificate Usage Field
 */
public class DomainIssuerCertificateVerifier extends BaseCertificateVerifier {
    private final Certificate domainIssuerCertificate;

    public DomainIssuerCertificateVerifier(Certificate domainIssuerCertificate) {
        Validate.notNull(domainIssuerCertificate);
        this.domainIssuerCertificate = domainIssuerCertificate;
    }

    @Override
    public CertPath verifyCertificate(boolean clientUsage, CertificateMessage message, InetSocketAddress peerSocket)
            throws HandshakeException {
        CertPath messageChain = message.getCertificateChain();

        validateCertificateChainNotEmpty(messageChain);

        X509Certificate receivedServerCertificate = validateReceivedCertificateIsSupported(messageChain);

        // - target certificate must match what is provided certificate in server info
        if (!domainIssuerCertificate.equals(receivedServerCertificate)) {
            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
            throw new HandshakeException("Certificate chain could not be validated", alert);
        }

        // - validate server name
        validateSubject(peerSocket, receivedServerCertificate);

        return messageChain;
    }
}
