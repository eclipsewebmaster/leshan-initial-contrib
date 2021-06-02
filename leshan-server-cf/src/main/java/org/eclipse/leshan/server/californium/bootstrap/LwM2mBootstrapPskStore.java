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
package org.eclipse.leshan.server.californium.bootstrap;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.eclipse.leshan.server.security.BootstrapSecurityStore;
import org.eclipse.leshan.server.security.SecurityInfo;

/**
 * PSK Store to feed a Bootstrap server.
 * 
 * Only supports getting the PSK key for a given identity. (Getting identity from IP only makes sense when we initiate
 * DTLS Connection) side.)
 */
public class LwM2mBootstrapPskStore implements AdvancedPskStore {

    private BootstrapSecurityStore bsSecurityStore;

    public LwM2mBootstrapPskStore(BootstrapSecurityStore bsSecurityStore) {
        this.bsSecurityStore = bsSecurityStore;
    }

    @Override
    public boolean hasEcdhePskSupported() {
        return true;
    }

    @Override
    public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
            PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed, boolean useExtendedMasterSecret) {
        SecurityInfo info = bsSecurityStore.getByIdentity(identity.getPublicInfoAsString());
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
        throw new UnsupportedOperationException("Getting PSK Id by IP addresss dos not make sense on BS server side.");
    }
}
