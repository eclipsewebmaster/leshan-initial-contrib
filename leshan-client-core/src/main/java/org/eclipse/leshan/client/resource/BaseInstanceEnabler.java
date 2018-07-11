/*******************************************************************************
 * Copyright (c) 2013-2018 Sierra Wireless and others.
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
 *     Achim Kraus (Bosch Software Innovations GmbH) - add reset() for 
 *                                                     REPLACE/UPDATE implementation
 *     Daniel Persson (Husqvarna Group) - attribute support
 *******************************************************************************/
package org.eclipse.leshan.client.resource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.leshan.Link;
import org.eclipse.leshan.client.util.DiscoverHelper;
import org.eclipse.leshan.core.attributes.AttributeSet;
import org.eclipse.leshan.core.node.LwM2mPath;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.response.DiscoverResponse;
import org.eclipse.leshan.core.response.ExecuteResponse;
import org.eclipse.leshan.core.response.ObserveResponse;
import org.eclipse.leshan.core.response.ReadResponse;
import org.eclipse.leshan.core.response.WriteAttributesResponse;
import org.eclipse.leshan.core.response.WriteResponse;

public class BaseInstanceEnabler implements LwM2mInstanceEnabler {

    private List<ResourceChangedListener> listeners = new ArrayList<>();
    private AttributeSet instanceAttributes;
    private Map<Integer, AttributeSet> resourceAttributes = new HashMap<>();

    /**
     * Gets the attributes that are attached to a specific resource.
     * @param resourceId
     * @return
     */
    protected AttributeSet getResourceAttributes(int resourceId) {
        return resourceAttributes.get(resourceId);
    }

    @Override
    public Collection<Integer> getAvailableResourceIds() {
        return new ArrayList<>();
    }
    
    @Override
    public void addResourceChangedListener(ResourceChangedListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeResourceChangedListener(ResourceChangedListener listener) {
        listeners.remove(listener);
    }

    public void fireResourcesChange(int... resourceIds) {
        for (ResourceChangedListener listener : listeners) {
            listener.resourcesChanged(resourceIds);
        }
    }

    @Override
    public ReadResponse read(int resourceid) {
        return ReadResponse.notFound();
    }

    @Override
    public WriteResponse write(int resourceid, LwM2mResource value) {
        return WriteResponse.notFound();
    }

    @Override
    public ExecuteResponse execute(int resourceid, String params) {
        return ExecuteResponse.notFound();
    }

    @Override
    public ObserveResponse observe(int resourceid) {
        // Perform a read by default
        ReadResponse readResponse = this.read(resourceid);
        return new ObserveResponse(readResponse.getCode(), readResponse.getContent(), null, null,
                readResponse.getErrorMessage());
    }

    @Override
    public DiscoverResponse discoverInstance(int objectId, AttributeSet objectAttributes, int instanceId) {
        List<Link> links = new ArrayList<>();
        // First add a link for the instance
        if (instanceAttributes == null || instanceAttributes.getMap().size() == 0) {
            links.add(new Link(new LwM2mPath(objectId, instanceId).toString()));
        } else {
            links.add(new Link(new LwM2mPath(objectId, instanceId).toString(), instanceAttributes));
        }
        
        for (int resourceId : getAvailableResourceIds()) {
            AttributeSet attrs = getResourceAttributes(resourceId);
            if (attrs == null || attrs.getMap().size() == 0) {
                links.add(new Link(new LwM2mPath(objectId, instanceId, resourceId).toString()));
            } else {
                links.add(new Link(new LwM2mPath(objectId, instanceId, resourceId).toString(), attrs));
            }
        }
        return DiscoverResponse.success(links.toArray(new Link[links.size()]));
    }

    @Override
    public DiscoverResponse discoverResource(int objectId, AttributeSet objectAttributes, int instanceId, int resourceId) {
        if (!getAvailableResourceIds().contains(resourceId)) {
            return DiscoverResponse.notFound();
        }
        return DiscoverResponse.success(new Link[] {
                DiscoverHelper.resourceLink(objectId, objectAttributes, instanceId, instanceAttributes,
                        resourceId, resourceAttributes.get(resourceId))
        });
    }

    @Override
    public void reset(int resourceid) {
        // No default behavior
    }

    @Override
    public WriteAttributesResponse writeInstanceAttributes(AttributeSet attributes) {
        if (this.instanceAttributes == null) {
            this.instanceAttributes = attributes;
        } else {
            this.instanceAttributes = this.instanceAttributes.merge(attributes);
        }
        return WriteAttributesResponse.success();
    }

    @Override
    public WriteAttributesResponse writeResourceAttributes(int resourceId, AttributeSet attributes) {
        ReadResponse readResponse = read(resourceId);
        if (readResponse == null) {
            return WriteAttributesResponse.notFound();
        } else if (!readResponse.isSuccess()) {
            return new WriteAttributesResponse(readResponse.getCode(), readResponse.getErrorMessage());
        }
        AttributeSet existingSet = resourceAttributes.get(resourceId);
        if (existingSet == null) {
            resourceAttributes.put(resourceId, attributes);
        } else {
            resourceAttributes.put(resourceId, existingSet.merge(attributes));
        }
        return WriteAttributesResponse.success();
    }
}
