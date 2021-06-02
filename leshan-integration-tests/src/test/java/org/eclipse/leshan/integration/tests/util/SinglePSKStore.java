/*******************************************************************************
 * Copyright (c) 2018 Sierra Wireless and others.
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
package org.eclipse.leshan.integration.tests.util;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

public class SinglePSKStore implements AdvancedPskStore {

    private PskPublicInformation identity;
    private SecretKey key;

    public SinglePSKStore(PskPublicInformation identity, byte[] key) {
        this.identity = identity;
        this.key = SecretUtil.create(key, "PSK");
    }

    public SinglePSKStore(PskPublicInformation identity, SecretKey key) {
        this.identity = identity;
        this.key = key;
    }

    @Override
    public boolean hasEcdhePskSupported() {
        return true;
    }

    @Override
    public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
            PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed, boolean useExtendedMasterSecret) {
        SecretKey pskSecret = SecretUtil.create(key);
        return new PskSecretResult(cid, identity, pskSecret);
    }

    @Override
    public void setResultHandler(org.eclipse.californium.scandium.dtls.HandshakeResultHandler resultHandler) {
        // we don't use async mode.
    }

    @Override
    public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
        return identity;
    }

    public void setKey(byte[] key) {
        this.key = SecretUtil.create(key, "PSK");
    }

    public void setIdentity(String identity) {
        this.identity = new PskPublicInformation(identity);
    }
}
