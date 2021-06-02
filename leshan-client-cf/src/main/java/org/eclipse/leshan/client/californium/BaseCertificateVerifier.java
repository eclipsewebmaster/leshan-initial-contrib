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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.ServerNames;
import org.eclipse.leshan.core.util.X509CertUtil;

public abstract class BaseCertificateVerifier implements NewAdvancedCertificateVerifier {

    private final List<CertificateType> supportedCertificateType = Arrays.asList(CertificateType.X_509);

    @Override
    public List<CertificateType> getSupportedCertificateTypes() {
        return supportedCertificateType;
    }

    @Override
    public void setResultHandler(HandshakeResultHandler resultHandler) {
        // we don't use async mode.
    }

    @Override
    public List<X500Principal> getAcceptedIssuers() {
        return Collections.emptyList();
    }

    @Override
    public CertificateVerificationResult verifyCertificate(ConnectionId cid, ServerNames serverName,
            InetSocketAddress remotePeer, boolean clientUsage, boolean truncateCertificatePath, CertificateMessage message) {
        try {
            CertPath validatedCertPath = verifyCertificate(clientUsage, message, remotePeer);
            return new CertificateVerificationResult(cid, validatedCertPath, null);
        } catch (HandshakeException exception) {
            return new CertificateVerificationResult(cid, exception, null);
        }
    }

    protected abstract CertPath verifyCertificate(boolean clientUsage, CertificateMessage message, InetSocketAddress peerSocket)
            throws HandshakeException;

    /**
     * Ensure that chain is not empty
     */
    protected void validateCertificateChainNotEmpty(CertPath certChain)
            throws HandshakeException {
        if (certChain.getCertificates().size() == 0) {
            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
            throw new HandshakeException("Certificate chain could not be validated : server cert chain is empty",
                    alert);
        }
    }

    /**
     * Ensure that received certificate is x509 certificate
     */
    protected X509Certificate validateReceivedCertificateIsSupported(CertPath certChain) throws HandshakeException {
        Certificate receivedServerCertificate = certChain.getCertificates().get(0);
        if (!(receivedServerCertificate instanceof X509Certificate)) {
            AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_CERTIFICATE);
            throw new HandshakeException("Certificate chain could not be validated - unknown certificate type", alert);
        }
        return (X509Certificate) receivedServerCertificate;
    }

    protected void validateSubject(final InetSocketAddress peerSocket, final X509Certificate receivedServerCertificate)
            throws HandshakeException {

        if (X509CertUtil.matchSubjectDnsName(receivedServerCertificate, peerSocket.getHostName()))
            return;

        if (X509CertUtil.matchSubjectInetAddress(receivedServerCertificate, peerSocket.getAddress()))
            return;

        AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
        throw new HandshakeException(
                "Certificate chain could not be validated - server identity does not match certificate", alert);
    }
}
