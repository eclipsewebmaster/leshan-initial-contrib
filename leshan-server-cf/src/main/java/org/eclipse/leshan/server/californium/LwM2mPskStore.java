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
 *     Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.leshan.server.californium;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.eclipse.leshan.server.registration.Registration;
import org.eclipse.leshan.server.registration.RegistrationStore;
import org.eclipse.leshan.server.security.SecurityInfo;
import org.eclipse.leshan.server.security.SecurityStore;

/**
 * A {@link AdvancedPskStore} which retrieve PSK information from Leshan {@link SecurityStore}.
 */
public class LwM2mPskStore implements AdvancedPskStore {

    private SecurityStore securityStore;
    private RegistrationStore registrationStore;

    public LwM2mPskStore(SecurityStore securityStore) {
        this(securityStore, null);
    }

    public LwM2mPskStore(SecurityStore securityStore, RegistrationStore registrationStore) {
        this.securityStore = securityStore;
        this.registrationStore = registrationStore;
    }

    @Override
    public boolean hasEcdhePskSupported() {
        return true;
    }

    @Override
    public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
            PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed, boolean useExtendedMasterSecret) {
        if (securityStore == null)
            return null;

        SecurityInfo info = securityStore.getByIdentity(identity.getPublicInfoAsString());
        if (info == null || info.getPreSharedKey() == null) {
            return new PskSecretResult(cid, identity, null);
        } else {
            // defensive copy
            return new PskSecretResult(cid, identity, SecretUtil.create(info.getPreSharedKey(), "PSK"));
        }
    }

    @Override
    public void setResultHandler(org.eclipse.californium.scandium.dtls.HandshakeResultHandler resultHandler) {
        // we don't use async mode.
    }

    @Override
    public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
        if (registrationStore == null)
            return null;

        Registration registration = registrationStore.getRegistrationByAdress(peerAddress);
        if (registration != null) {
            SecurityInfo securityInfo = securityStore.getByEndpoint(registration.getEndpoint());
            if (securityInfo != null) {
                return new PskPublicInformation(securityInfo.getIdentity());
            }
            return null;
        }
        return null;
    }
}
