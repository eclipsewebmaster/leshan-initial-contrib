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
 *     Achim Kraus (Bosch Software Innovations GmbH) - use ServerIdentity
 *******************************************************************************/
package org.eclipse.leshan.client.californium;

import static org.eclipse.leshan.core.californium.ResponseCodeUtil.toCoapResponseCode;

import java.util.List;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.leshan.client.bootstrap.BootstrapHandler;
import org.eclipse.leshan.client.engine.RegistrationEngine;
import org.eclipse.leshan.client.resource.LwM2mRootEnabler;
import org.eclipse.leshan.client.servers.ServerIdentity;
import org.eclipse.leshan.core.Link;
import org.eclipse.leshan.core.node.LwM2mNode;
import org.eclipse.leshan.core.node.LwM2mPath;
import org.eclipse.leshan.core.node.codec.LwM2mDecoder;
import org.eclipse.leshan.core.node.codec.LwM2mEncoder;
import org.eclipse.leshan.core.request.BootstrapDeleteRequest;
import org.eclipse.leshan.core.request.BootstrapDiscoverRequest;
import org.eclipse.leshan.core.request.ContentFormat;
import org.eclipse.leshan.core.request.ReadCompositeRequest;
import org.eclipse.leshan.core.request.WriteCompositeRequest;
import org.eclipse.leshan.core.response.BootstrapDeleteResponse;
import org.eclipse.leshan.core.response.BootstrapDiscoverResponse;
import org.eclipse.leshan.core.response.ReadCompositeResponse;
import org.eclipse.leshan.core.response.WriteCompositeResponse;
import org.eclipse.leshan.core.util.StringUtils;

/**
 * A root {@link CoapResource} resource in charge of handling Bootstrap Delete requests targeting the "/" URI.
 */
public class RootResource extends LwM2mClientCoapResource {

    protected CoapServer coapServer;
    protected BootstrapHandler bootstrapHandler;
    protected LwM2mRootEnabler rootEnabler;
    protected LwM2mEncoder encoder;
    protected LwM2mDecoder decoder;

    public RootResource(RegistrationEngine registrationEngine, CaliforniumEndpointsManager endpointsManager,
            BootstrapHandler bootstrapHandler, CoapServer coapServer, LwM2mRootEnabler rootEnabler,
            LwM2mEncoder encoder, LwM2mDecoder decoder) {
        super("", registrationEngine, endpointsManager);
        this.bootstrapHandler = bootstrapHandler;
        setVisible(false);
        this.coapServer = coapServer;
        this.rootEnabler = rootEnabler;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    @Override
    public void handleGET(CoapExchange exchange) {
        ServerIdentity identity = getServerOrRejectRequest(exchange);
        if (identity == null)
            return;

        String URI = exchange.getRequestOptions().getUriPathString();

        // Manage Bootstrap Discover Request
        Request coapRequest = exchange.advanced().getRequest();
        BootstrapDiscoverResponse response = bootstrapHandler.discover(identity,
                new BootstrapDiscoverRequest(URI, coapRequest));
        if (response.getCode().isError()) {
            exchange.respond(toCoapResponseCode(response.getCode()), response.getErrorMessage());
        } else {
            exchange.respond(toCoapResponseCode(response.getCode()), Link.serialize(response.getObjectLinks()),
                    MediaTypeRegistry.APPLICATION_LINK_FORMAT);
        }
        return;
    }

    @Override
    public void handleFETCH(CoapExchange exchange) {
        ServerIdentity identity = getServerOrRejectRequest(exchange);
        if (identity == null)
            return;

        // Manage Read Composite request
        Request coapRequest = exchange.advanced().getRequest();

        // Handle content format for the response
        ContentFormat responseContentFormat = ContentFormat.SENML_CBOR; // use CBOR as default
        if (exchange.getRequestOptions().hasAccept()) {
            // If an request ask for a specific content format, use it (if we support it)
            responseContentFormat = ContentFormat.fromCode(exchange.getRequestOptions().getAccept());
            if (!encoder.isSupported(responseContentFormat)) {
                exchange.respond(ResponseCode.NOT_ACCEPTABLE);
                return;
            }
        }

        // Decode Path to read
        if (!exchange.getRequestOptions().hasContentFormat()) {
            exchange.respond(ResponseCode.BAD_REQUEST);
            return;
        }
        ContentFormat requestContentFormat = ContentFormat.fromCode(exchange.getRequestOptions().getContentFormat());
        List<LwM2mPath> paths = decoder.decodePaths(coapRequest.getPayload(), requestContentFormat);

        ReadCompositeResponse response = rootEnabler.read(identity,
                new ReadCompositeRequest(paths, requestContentFormat, responseContentFormat, coapRequest));
        if (response.getCode().isError()) {
            exchange.respond(toCoapResponseCode(response.getCode()), response.getErrorMessage());
        } else {
            // TODO we could maybe face some race condition if an objectEnabler is removed from LwM2mObjectTree between
            // rootEnabler.read() and rootEnabler.getModel()
            exchange.respond(toCoapResponseCode(response.getCode()),
                    encoder.encodeNodes(response.getContent(), responseContentFormat, rootEnabler.getModel()),
                    responseContentFormat.getCode());
        }
        return;
    }

    @Override
    public void handleIPATCH(CoapExchange exchange) {
        ServerIdentity identity = getServerOrRejectRequest(exchange);
        if (identity == null)
            return;

        // Manage Read Composite request
        Request coapRequest = exchange.advanced().getRequest();

        // Handle content format
        ContentFormat contentFormat = ContentFormat.fromCode(exchange.getRequestOptions().getContentFormat());
        if (!decoder.isSupported(contentFormat)) {
            exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT);
            return;
        }

        Map<LwM2mPath, LwM2mNode> nodes = decoder.decodeNodes(coapRequest.getPayload(), contentFormat, null,
                rootEnabler.getModel());

        WriteCompositeResponse response = rootEnabler.write(identity,
                new WriteCompositeRequest(contentFormat, nodes, coapRequest));
        if (response.getCode().isError()) {
            exchange.respond(toCoapResponseCode(response.getCode()), response.getErrorMessage());
        } else {
            exchange.respond(toCoapResponseCode(response.getCode()));
        }
        return;
    }

    @Override
    public void handleDELETE(CoapExchange exchange) {
        String URI = exchange.getRequestOptions().getUriPathString();
        if (!StringUtils.isEmpty(URI)) {
            exchange.respond(ResponseCode.METHOD_NOT_ALLOWED);
            return;
        }

        ServerIdentity identity = getServerOrRejectRequest(exchange);
        if (identity == null)
            return;

        Request coapRequest = exchange.advanced().getRequest();
        BootstrapDeleteResponse response = bootstrapHandler.delete(identity,
                new BootstrapDeleteRequest(URI, coapRequest));
        exchange.respond(toCoapResponseCode(response.getCode()), response.getErrorMessage());
    }

}
