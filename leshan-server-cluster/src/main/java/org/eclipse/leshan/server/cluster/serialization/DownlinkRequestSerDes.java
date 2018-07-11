/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *     Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.leshan.server.cluster.serialization;

import java.util.ArrayList;
import java.util.Collection;

import org.eclipse.leshan.ObserveSpec;
import org.eclipse.leshan.core.node.LwM2mNode;
import org.eclipse.leshan.core.node.LwM2mObjectInstance;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.request.ContentFormat;
import org.eclipse.leshan.core.request.CreateRequest;
import org.eclipse.leshan.core.request.DeleteRequest;
import org.eclipse.leshan.core.request.DiscoverRequest;
import org.eclipse.leshan.core.request.DownLinkRequestVisitorAdapter;
import org.eclipse.leshan.core.request.DownlinkRequest;
import org.eclipse.leshan.core.request.ExecuteRequest;
import org.eclipse.leshan.core.request.ObserveRequest;
import org.eclipse.leshan.core.request.ReadRequest;
import org.eclipse.leshan.core.request.WriteAttributesRequest;
import org.eclipse.leshan.core.request.WriteRequest;
import org.eclipse.leshan.core.request.WriteRequest.Mode;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;

/**
 * Functions for serialize and deserialize a LWM2M Downlink request in JSON.
 */
public class DownlinkRequestSerDes {

    public static JsonObject jSerialize(DownlinkRequest<?> r) {
        final JsonObject o = Json.object();
        o.add("path", r.getPath().toString());

        r.accept(new DownLinkRequestVisitorAdapter() {
            @Override
            public void visit(ObserveRequest request) {
                o.add("kind", "observe");
                if (request.getContentFormat() != null)
                    o.add("contentFormat", request.getContentFormat().getCode());
            }

            @Override
            public void visit(DeleteRequest request) {
                o.add("kind", "delete");
            }

            @Override
            public void visit(DiscoverRequest request) {
                o.add("kind", "discover");
            }

            @Override
            public void visit(CreateRequest request) {
                o.add("kind", "create");
                o.add("contentFormat", request.getContentFormat().getCode());
                if (request.getInstanceId() != null)
                    o.add("instanceId", request.getInstanceId());

                JsonArray resources = new JsonArray();
                for (LwM2mResource resource : request.getResources()) {
                    resources.add(LwM2mNodeSerDes.jSerialize(resource));
                }
                o.add("resources", resources);
            }

            @Override
            public void visit(ExecuteRequest request) {
                o.add("kind", "execute");
                o.add("parameters", request.getParameters());
            }

            @Override
            public void visit(WriteAttributesRequest request) {
                o.add("kind", "writeAttributes");
                o.add("observeSpec", request.getAttributes().toString());
            }

            @Override
            public void visit(WriteRequest request) {
                o.add("kind", "write");
                o.add("contentFormat", request.getContentFormat().getCode());
                o.add("mode", request.isPartialUpdateRequest() ? "UPDATE" : "REPLACE");
                o.add("node", LwM2mNodeSerDes.jSerialize(request.getNode()));
            }

            @Override
            public void visit(ReadRequest request) {
                o.add("kind", "read");
                if (request.getContentFormat() != null)
                    o.add("contentFormat", request.getContentFormat().getCode());
            }
        });
        return o;
    }

    public static String sSerialize(DownlinkRequest<?> r) {
        return jSerialize(r).toString();
    }

    public static byte[] bSerialize(DownlinkRequest<?> r) {
        return jSerialize(r).toString().getBytes();
    }

    public static DownlinkRequest<?> deserialize(JsonObject o) {
        String kind = o.getString("kind", null);
        String path = o.getString("path", null);
        switch (kind) {
        case "observe": {
            int format = o.getInt("contentFormat", ContentFormat.TLV.getCode());
            return new ObserveRequest(ContentFormat.fromCode(format), path);
        }
        case "delete":
            return new DeleteRequest(path);
        case "discover":
            return new DiscoverRequest(path);
        case "create": {
            int format = o.getInt("contentFormat", ContentFormat.TLV.getCode());
            int instanceId = o.getInt("instanceId", LwM2mObjectInstance.UNDEFINED);

            Collection<LwM2mResource> resources = new ArrayList<>();
            JsonArray jResources = (JsonArray) o.get("resources");
            for (JsonValue jResource : jResources) {
                LwM2mResource resource = (LwM2mResource) LwM2mNodeSerDes.deserialize((JsonObject) jResource);
                resources.add(resource);
            }
            return new CreateRequest(ContentFormat.fromCode(format), path,
                    new LwM2mObjectInstance(instanceId, resources));
        }
        case "execute":
            String parameters = o.getString("parameters", null);
            return new ExecuteRequest(path, parameters);
        case "writeAttributes": {
            String observeSpec = o.getString("observeSpec", null);
            return new WriteAttributesRequest(path, ObserveSpec.parse(observeSpec));
        }
        case "write": {
            int format = o.getInt("contentFormat", ContentFormat.TLV.getCode());
            Mode mode = o.getString("mode", "REPLACE").equals("REPLACE") ? Mode.REPLACE : Mode.UPDATE;
            LwM2mNode node = LwM2mNodeSerDes.deserialize((JsonObject) o.get("node"));
            return new WriteRequest(mode, ContentFormat.fromCode(format), path, node);
        }
        case "read": {
            int format = o.getInt("contentFormat", ContentFormat.TLV.getCode());
            return new ReadRequest(ContentFormat.fromCode(format), path);
        }
        default:
            throw new IllegalStateException("Invalid request missing kind attribute");
        }
    }

}