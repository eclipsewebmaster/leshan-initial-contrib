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
 *     Daniel Persson (Husqvarna Group) - Attribute support
 *******************************************************************************/
package org.eclipse.leshan.client.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.eclipse.leshan.Link;
import org.eclipse.leshan.client.resource.LwM2mInstanceEnabler;
import org.eclipse.leshan.core.attributes.Attachment;
import org.eclipse.leshan.core.attributes.AttributeSet;
import org.eclipse.leshan.core.node.LwM2mPath;
import org.eclipse.leshan.core.response.DiscoverResponse;

/**
 * Helper class for creating {@link Link} objects in response to a DiscoverRequest on either
 * object, instance or resource level.
 */
public class DiscoverHelper {

    private static Link newLink(int objectId, AttributeSet attributes) {
        return new Link(new LwM2mPath(objectId).toString(), attributes.getMap());
    }
    
    private static void addObjectLinks(List<Link> links, int objectId, AttributeSet objectAttributes,
            Map<Integer, LwM2mInstanceEnabler> instances) {
        links.add(newLink(objectId, objectAttributes));
        for (Entry<Integer, LwM2mInstanceEnabler> entry : instances.entrySet()) {
            addInstanceLinksWithoutAttributes(links, objectId, objectAttributes, entry.getKey(), entry.getValue());
        }
    }
    
    private static void addInstanceLinksWithoutAttributes(List<Link> links, int objectId, AttributeSet objectAttributes,
            int instanceId, LwM2mInstanceEnabler instance) {
        // Get the instance links but remove their attributes 
        DiscoverResponse instanceDiscover = instance.discoverInstance(objectId, objectAttributes, instanceId);
        for (Link link : instanceDiscover.getObjectLinks()) {
            links.add(new Link(link.getUrl()));
        }
    }
    
    /**
     * Creates Discover Links on the object level. Attributes that are attached on the object level are reported,
     * all instance and instance resource links are reported without their attributes.
     * @return
     */
    public static Link[] objectLinks(int objectId, AttributeSet objectAttributes,
            Map<Integer, LwM2mInstanceEnabler> instances) {
        List<Link> links = new ArrayList<>();
        addObjectLinks(links, objectId, objectAttributes, instances);        
        return links.toArray(new Link[links.size()]);        
    }
    
    /**
     * Creates a Discover link on the resource level. The link should include all R-attributes that are attached on the
     * object or instance level, or on the resource itself. The attributes take precedence over the attributes on the
     * instance level, and the instance level attributes take precedence over the attributes on the object level.
     */
    public static Link resourceLink(int objectId, AttributeSet objectAttributes,
            int instanceId, AttributeSet instanceAttributes, int resourceId, AttributeSet resourceAttributes) {
        AttributeSet attrs = new AttributeSet();
        if (objectAttributes != null) {
            attrs = attrs.merge(objectAttributes.filter(Attachment.RESOURCE));
        }
        if (instanceAttributes != null) {
            attrs = attrs.merge(instanceAttributes.filter(Attachment.RESOURCE));
        }
        if (resourceAttributes != null) {
            attrs = attrs.merge(resourceAttributes);
        }
        return new Link(new LwM2mPath(objectId, instanceId, resourceId).toString(), attrs);
    }
}
