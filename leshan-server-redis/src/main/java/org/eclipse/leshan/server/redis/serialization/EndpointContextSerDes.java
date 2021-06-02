/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.leshan.server.redis.serialization;

import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.leshan.core.util.Hex;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;

/**
 * Functions for serializing and deserializing a Californium {@link EndpointContext} in JSON.
 */
public class EndpointContextSerDes {

    private static final String KEY_ADDRESS = "address";
    private static final String KEY_PORT = "port";
    private static final String KEY_ID = "id";
    private static final String KEY_DN = "dn";
    private static final String KEY_RPK = "rpk";
    private static final String KEY_ATTRIBUTES = "attributes";

    public static JsonObject serialize(EndpointContext context) {
        JsonObject peer = Json.object();
        peer.set(KEY_ADDRESS, context.getPeerAddress().getHostString());
        peer.set(KEY_PORT, context.getPeerAddress().getPort());
        Principal principal = context.getPeerIdentity();
        if (principal != null) {
            if (principal instanceof PreSharedKeyIdentity) {
                peer.set(KEY_ID, ((PreSharedKeyIdentity) principal).getIdentity());
            } else if (principal instanceof RawPublicKeyIdentity) {
                PublicKey publicKey = ((RawPublicKeyIdentity) principal).getKey();
                peer.set(KEY_RPK, Hex.encodeHexString(publicKey.getEncoded()));
            } else if (principal instanceof X500Principal || principal instanceof X509CertPath) {
                peer.set(KEY_DN, principal.getName());
            }
        }
        /** copy the attributes **/
        Map<String, Object> attributes = context.entries();
        if (!attributes.isEmpty()) {
            DatagramWriter writer = new DatagramWriter();
            SerializationUtil.write(writer, attributes);
            String base64 = StringUtil.byteArrayToBase64(writer.toByteArray());
            peer.set(KEY_ATTRIBUTES, base64);
        }
        return peer;
    }

    public static EndpointContext deserialize(JsonObject peer) {

        String address = peer.get(KEY_ADDRESS).asString();
        int port = peer.get(KEY_PORT).asInt();
        InetSocketAddress socketAddress = new InetSocketAddress(address, port);

        Principal principal = null;
        JsonValue value = peer.get(KEY_ID);
        if (value != null) {
            principal = new PreSharedKeyIdentity(value.asString());
        } else if ((value = peer.get(KEY_RPK)) != null) {
            try {
                byte[] rpk = Hex.decodeHex(value.asString().toCharArray());
                X509EncodedKeySpec spec = new X509EncodedKeySpec(rpk);
                PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(spec);
                principal = new RawPublicKeyIdentity(publicKey);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                throw new IllegalStateException("Invalid security info content", e);
            }
        } else if ((value = peer.get(KEY_DN)) != null) {
            principal = new X500Principal(value.asString());
        }

        EndpointContext endpointContext;
        value = peer.get(KEY_ATTRIBUTES);
        if (value == null) {
            endpointContext = new AddressEndpointContext(socketAddress, principal);
        } else {
            String base64 = value.asString();
            byte[] data = StringUtil.base64ToByteArray(base64);
            DatagramReader reader = new DatagramReader(data, false);
            Attributes contexAttributes = SerializationUtil.readEndpointContexAttributes(reader);
            endpointContext = new MapBasedEndpointContext(socketAddress, principal, contexAttributes);
        }
        return endpointContext;
    }

}
