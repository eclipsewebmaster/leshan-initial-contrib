/*******************************************************************************
 * Copyright (c) 2013-2015 Sierra Wireless and others.
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
package org.eclipse.leshan;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.eclipse.leshan.core.attributes.AttributeSet;
import org.eclipse.leshan.util.StringUtils;

/**
 * A Link as defined in http://tools.ietf.org/html/rfc6690.
 */
// TODO we should have a look at org.eclipse.californium.core.coap.LinkFormat
public class Link implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String url;

    private final Map<String, Object> attributes;

    /**
     * Creates a new Link without attributes.
     * 
     * @param url the object link URL
     */
    public Link(String url) {
        this(url, (Map<String, ?>) null);
    }

    /**
     * Creates a new link and with its attributes.
     * 
     * @param url the link URL
     * @param attributes the object link attributes or <code>null</code> if the link has no attributes
     */
    public Link(String url, Map<String, ?> attributes) {
        this.url = url;
        if (attributes != null) {
            this.attributes = Collections.unmodifiableMap(new HashMap<>(attributes));
        } else {
            this.attributes = Collections.emptyMap();
        }
    }

    /**
     * Creates a new link with a set of attributes that is attached to it.
     * @param url the link URL
     * @param attributes the attribute set
     */
    public Link(String url, AttributeSet attributes) {
        this(url, attributes == null ? null : attributes.getMap());
    }
    
    public String getUrl() {
        return url;
    }

    /**
     * Gets the link attributes
     * 
     * @return an unmodifiable map containing the link attributes
     */
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append('<');
        builder.append(getUrl());
        builder.append('>');

        Map<String, Object> attributes = getAttributes();
        if (attributes != null && !attributes.isEmpty()) {
            for (Entry<String, Object> entry : attributes.entrySet()) {
                builder.append(";");
                builder.append(entry.getKey());
                if (entry.getValue() != null) {
                    builder.append("=");
                    if (entry.getValue() instanceof String) {
                        builder.append("\"").append(entry.getValue()).append("\"");
                    } else {
                        builder.append(entry.getValue());
                    }
                }
            }
        }
        return builder.toString();
    }

    public static Link[] parse(byte[] content) {
        if (content == null) {
            return new Link[] {};
        }
        String s = new String(content, StandardCharsets.UTF_8);
        String[] links = s.split(",");
        Link[] linksResult = new Link[links.length];
        int index = 0;
        for (String link : links) {
            String[] linkParts = link.split(";");

            // clean URL
            String url = StringUtils.trim(linkParts[0]);
            url = StringUtils.removeStart(StringUtils.removeEnd(url, ">"), "<");

            // parse attributes
            Map<String, Object> attributes = new HashMap<>();

            if (linkParts.length > 1) {
                for (int i = 1; i < linkParts.length; i++) {
                    String[] attParts = linkParts[i].split("=");
                    if (attParts.length > 0) {
                        String key = attParts[0];
                        Object value = null;
                        if (attParts.length > 1) {
                            String rawvalue = attParts[1];
                            try {
                                value = Integer.valueOf(rawvalue);
                            } catch (NumberFormatException e) {

                                value = rawvalue.replaceFirst("^\"(.*)\"$", "$1");
                            }
                        }
                        attributes.put(key, value);
                    }
                }
            }
            linksResult[index] = new Link(url, attributes);
            index++;
        }
        return linksResult;
    }

    public static final String INVALID_LINK_PAYLOAD = "<>";
    private static final String TRAILER = ", ";

    public static String serialize(Link... linkObjects) {
        try {
            StringBuilder builder = new StringBuilder();
            for (Link link : linkObjects) {
                builder.append(link.toString()).append(TRAILER);
            }

            builder.delete(builder.length() - TRAILER.length(), builder.length());

            return builder.toString();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
        result = prime * result + ((url == null) ? 0 : url.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Link other = (Link) obj;
        if (attributes == null) {
            if (other.attributes != null)
                return false;
        } else if (!attributes.equals(other.attributes))
            return false;
        if (url == null) {
            if (other.url != null)
                return false;
        } else if (!url.equals(other.url))
            return false;
        return true;
    }
}
