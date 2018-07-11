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
package org.eclipse.leshan.core.request;

import org.eclipse.leshan.ObserveSpec;
import org.eclipse.leshan.core.attributes.AttributeSet;
import org.eclipse.leshan.core.node.LwM2mPath;
import org.eclipse.leshan.core.request.exception.InvalidRequestException;
import org.eclipse.leshan.core.response.WriteAttributesResponse;

public class WriteAttributesRequest extends AbstractDownlinkRequest<WriteAttributesResponse> {

    private final AttributeSet attributes;

    public WriteAttributesRequest(int objectId, AttributeSet attributes) throws InvalidRequestException {
        this(new LwM2mPath(objectId), attributes);
    }

    public WriteAttributesRequest(int objectId, int objectInstanceId, AttributeSet attributes) throws InvalidRequestException {
        this(new LwM2mPath(objectId, objectInstanceId), attributes);
    }

    public WriteAttributesRequest(int objectId, int objectInstanceId, int resourceId, AttributeSet attributes) throws InvalidRequestException {
        this(new LwM2mPath(objectId, objectInstanceId, resourceId), attributes);
    }

    public WriteAttributesRequest(String path, ObserveSpec observeSpec) throws InvalidRequestException {
        this(newPath(path), new AttributeSet(observeSpec.toQueryParams()));
    }

    public WriteAttributesRequest(int objectId, int objectInstanceId, int resourceId, ObserveSpec observeSpec) throws InvalidRequestException {
        this(new LwM2mPath(objectId, objectInstanceId, resourceId), new AttributeSet(observeSpec.toQueryParams()));
    }

    public WriteAttributesRequest(String path, AttributeSet attributes) {
        this(newPath(path), attributes);
    }

    private WriteAttributesRequest(LwM2mPath path, AttributeSet attributes) throws InvalidRequestException {
        super(path);
        if (attributes == null)
            throw new InvalidRequestException("attributes are mandatory for %s", path);
        this.attributes = attributes;
    }

    @Override
    public void accept(DownlinkRequestVisitor visitor) {
        visitor.visit(this);
    }

    public AttributeSet getAttributes() {
        return this.attributes;
    }

    @Override
    public String toString() {
        return String.format("WriteAttributesRequest [%s, attributes=%s]", getPath(), getAttributes());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        WriteAttributesRequest other = (WriteAttributesRequest) obj;
        if (attributes == null) {
            if (other.attributes != null)
                return false;
        } else if (!attributes.equals(other.attributes))
            return false;
        return true;
    }
}
