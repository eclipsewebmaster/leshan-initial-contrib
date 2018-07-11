/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless and others.
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
 *     Achim Kraus (Bosch Software Innovations GmbH) - deny delete of resource
 *     Achim Kraus (Bosch Software Innovations GmbH) - use ServerIdentity to 
 *                                                     protect the security object
 *     Achim Kraus (Bosch Software Innovations GmbH) - add resource checks for 
 *                                                     REPLACE/UPDAT implementation
 *******************************************************************************/
package org.eclipse.leshan.client.resource;

import java.util.HashSet;
import java.util.Set;

import org.eclipse.leshan.Link;
import org.eclipse.leshan.LwM2mId;
import org.eclipse.leshan.client.request.ServerIdentity;
import org.eclipse.leshan.client.util.LinkFormatHelper;
import org.eclipse.leshan.core.model.ObjectModel;
import org.eclipse.leshan.core.model.ResourceModel;
import org.eclipse.leshan.core.node.LwM2mObjectInstance;
import org.eclipse.leshan.core.node.LwM2mPath;
import org.eclipse.leshan.core.request.BootstrapWriteRequest;
import org.eclipse.leshan.core.request.CreateRequest;
import org.eclipse.leshan.core.request.DeleteRequest;
import org.eclipse.leshan.core.request.DiscoverRequest;
import org.eclipse.leshan.core.request.ExecuteRequest;
import org.eclipse.leshan.core.request.ObserveRequest;
import org.eclipse.leshan.core.request.ReadRequest;
import org.eclipse.leshan.core.request.WriteAttributesRequest;
import org.eclipse.leshan.core.request.WriteRequest;
import org.eclipse.leshan.core.response.BootstrapWriteResponse;
import org.eclipse.leshan.core.response.CreateResponse;
import org.eclipse.leshan.core.response.DeleteResponse;
import org.eclipse.leshan.core.response.DiscoverResponse;
import org.eclipse.leshan.core.response.ExecuteResponse;
import org.eclipse.leshan.core.response.ObserveResponse;
import org.eclipse.leshan.core.response.ReadResponse;
import org.eclipse.leshan.core.response.WriteAttributesResponse;
import org.eclipse.leshan.core.response.WriteResponse;

public abstract class BaseObjectEnabler implements LwM2mObjectEnabler {

    final int id;
    private NotifySender notifySender;
    private ObjectModel objectModel;

    public BaseObjectEnabler(int id, ObjectModel objectModel) {
        this.id = id;
        this.objectModel = objectModel;
    }

    @Override
    public synchronized int getId() {
        return id;
    }

    @Override
    public synchronized ObjectModel getObjectModel() {
        return objectModel;
    }

    @Override
    public synchronized CreateResponse create(ServerIdentity identity, CreateRequest request) {
        if (!identity.isSystem()) {
            // we can not create new instance on single object
            if (objectModel != null && !objectModel.multiple) {
                return CreateResponse.methodNotAllowed();
            }

            if (id == LwM2mId.SECURITY) {
                return CreateResponse.notFound();
            }
        }

        // TODO we could do a validation of request.getObjectInstance() by comparing with resourceSpec information.

        return doCreate(request);
    }

    protected CreateResponse doCreate(CreateRequest request) {
        // This should be a not implemented error, but this is not defined in the spec.
        return CreateResponse.internalServerError("not implemented");
    }

    @Override
    public synchronized ReadResponse read(ServerIdentity identity, ReadRequest request) {
        LwM2mPath path = request.getPath();

        // read is not supported for bootstrap
        if (identity.isLwm2mBootstrapServer()) {
            return ReadResponse.methodNotAllowed();
        }

        if (!identity.isSystem()) {
            // read the security object is forbidden
            if (id == LwM2mId.SECURITY) {
                return ReadResponse.notFound();
            }

            // check if the resource is readable.
            if (path.isResource()) {
                ResourceModel resourceModel = objectModel.resources.get(path.getResourceId());
                if (resourceModel != null && !resourceModel.operations.isReadable()) {
                    return ReadResponse.methodNotAllowed();
                }
            }
        }

        return doRead(identity, request);

        // TODO we could do a validation of response.getContent by comparing with the spec.
    }

    protected ReadResponse doRead(ServerIdentity identity, ReadRequest request) {
        // This should be a not implemented error, but this is not defined in the spec.
        return ReadResponse.internalServerError("not implemented");
    }

    @Override
    public synchronized WriteResponse write(ServerIdentity identity, WriteRequest request) {
        LwM2mPath path = request.getPath();

        // write is not supported for bootstrap, use bootstrap write
        if (identity.isLwm2mBootstrapServer()) {
            return WriteResponse.methodNotAllowed();
        }

        // write the security object is forbidden
        if (LwM2mId.SECURITY == id && !identity.isSystem()) {
            return WriteResponse.notFound();
        }

        if (path.isResource()) {
            // resource write:
            // check if the resource is writable
            if (LwM2mId.SECURITY != id) { // security resources are writable by SYSTEM
                ResourceModel resourceModel = objectModel.resources.get(path.getResourceId());
                if (resourceModel != null && !resourceModel.operations.isWritable()) {
                    return WriteResponse.methodNotAllowed();
                }
            }
        } else if (path.isObjectInstance()) {
            // instance write:
            // check if all resources are writable
            if (LwM2mId.SECURITY != id) { // security resources are writable by SYSTEM
                ObjectModel model = getObjectModel();
                for (Integer writeResourceId : ((LwM2mObjectInstance) request.getNode()).getResources().keySet()) {
                    ResourceModel resourceModel = model.resources.get(writeResourceId);
                    if (null != resourceModel && !resourceModel.operations.isWritable()) {
                        return WriteResponse.methodNotAllowed();
                    }
                }
            }

            if (request.isReplaceRequest()) {
                // REPLACE
                // check, if all mandatory writable resources are provided
                // Collect all mandatory writable resource IDs from the model
                Set<Integer> mandatoryResources = new HashSet<>();
                for (ResourceModel resourceModel : getObjectModel().resources.values()) {
                    if (resourceModel.mandatory && (LwM2mId.SECURITY == id || resourceModel.operations.isWritable()))
                        mandatoryResources.add(resourceModel.id);
                }
                // Afterwards remove the provided resource IDs from that set
                for (Integer writeResourceId : ((LwM2mObjectInstance) request.getNode()).getResources().keySet()) {
                    mandatoryResources.remove(writeResourceId);
                }
                if (!mandatoryResources.isEmpty()) {
                    return WriteResponse.badRequest("mandatory writable resources missing!");
                }
            }
        }

        // TODO we could do a validation of request.getNode() by comparing with resourceSpec information

        return doWrite(identity, request);
    }

    protected WriteResponse doWrite(ServerIdentity identity, WriteRequest request) {
        // This should be a not implemented error, but this is not defined in the spec.
        return WriteResponse.internalServerError("not implemented");
    }

    @Override
    public synchronized BootstrapWriteResponse write(ServerIdentity identity, BootstrapWriteRequest request) {

        // We should not get a bootstrapWriteRequest from a LWM2M server
        if (!identity.isLwm2mBootstrapServer()) {
            return BootstrapWriteResponse.internalServerError("bootstrap write request from LWM2M server");
        }

        return doWrite(identity, request);
    }

    protected BootstrapWriteResponse doWrite(ServerIdentity identity, BootstrapWriteRequest request) {
        // This should be a not implemented error, but this is not defined in the spec.
        return BootstrapWriteResponse.internalServerError("not implemented");
    }

    @Override
    public synchronized DeleteResponse delete(ServerIdentity identity, DeleteRequest request) {
        if (!identity.isLwm2mBootstrapServer() && !identity.isSystem()) {

            // delete the security object is forbidden
            if (id == LwM2mId.SECURITY) {
                return DeleteResponse.notFound();
            }

            // a resource can not be deleted
            LwM2mPath path = request.getPath();
            if (path.isResource()) {
                return DeleteResponse.methodNotAllowed();
            }

            // we can not delete instance on single object
            if (objectModel != null && !objectModel.multiple) {
                return DeleteResponse.methodNotAllowed();
            }
        }

        return doDelete(request);
    }

    protected DeleteResponse doDelete(DeleteRequest request) {
        // This should be a not implemented error, but this is not defined in the spec.
        return DeleteResponse.internalServerError("not implemented");
    }

    @Override
    public synchronized ExecuteResponse execute(ServerIdentity identity, ExecuteRequest request) {
        LwM2mPath path = request.getPath();

        // execute is not supported for bootstrap
        if (identity.isLwm2mBootstrapServer()) {
            return ExecuteResponse.methodNotAllowed();
        }

        // execute on security object is forbidden
        if (id == LwM2mId.SECURITY) {
            return ExecuteResponse.notFound();
        }

        // only resource could be executed
        if (!path.isResource()) {
            return ExecuteResponse.badRequest(null);
        }

        // check if the resource is writable
        ResourceModel resourceModel = objectModel.resources.get(path.getResourceId());
        if (resourceModel != null && !resourceModel.operations.isExecutable()) {
            return ExecuteResponse.methodNotAllowed();
        }

        return doExecute(request);
    }

    protected ExecuteResponse doExecute(ExecuteRequest request) {
        // This should be a not implemented error, but this is not defined in the spec.
        return ExecuteResponse.internalServerError("not implemented");
    }

    @Override
    public synchronized WriteAttributesResponse writeAttributes(ServerIdentity identity,
            WriteAttributesRequest request) {
        // write the security object is forbidden
        if (LwM2mId.SECURITY == id && !identity.isSystem()) {
            return WriteAttributesResponse.notFound();
        }
        
        // TODO Additional checks
        
        return doWriteAttributes(identity, request);
    }

    protected WriteAttributesResponse doWriteAttributes(ServerIdentity identity,
            WriteAttributesRequest request) {
        // This should be a not implemented error, but this is not defined in the spec.
        return WriteAttributesResponse.internalServerError("not implemented");
    }
    
    @Override
    public synchronized DiscoverResponse discover(ServerIdentity identity, DiscoverRequest request) {

        if (identity.isLwm2mBootstrapServer()) {
            // discover is not supported for bootstrap
            return DiscoverResponse.methodNotAllowed();
        }

        if (id == LwM2mId.SECURITY) {
            return DiscoverResponse.notFound();
        }
        
        return doDiscover(identity, request);
    }

    protected DiscoverResponse doDiscover(ServerIdentity identity, DiscoverRequest request) {
        // Use the object model as default provider for Discover
        LwM2mPath path = request.getPath();
        if (path.isObject()) {

            // Manage discover on object
            Link[] objectLinks = LinkFormatHelper.getObjectDescription(getObjectModel(), null);
            return DiscoverResponse.success(objectLinks);

        } else if (path.isObjectInstance()) {

            // Manage discover on instance
            if (!getAvailableInstanceIds().contains(path.getObjectInstanceId()))
                return DiscoverResponse.notFound();

            Link instanceLink = LinkFormatHelper.getInstanceDescription(getObjectModel(),
                    path.getObjectInstanceId(), null);
            return DiscoverResponse.success(new Link[] { instanceLink });

        } else if (path.isResource()) {
            // Manage discover on resource
            if (!getAvailableInstanceIds().contains(path.getObjectInstanceId()))
                return DiscoverResponse.notFound();

            ResourceModel resourceModel = getObjectModel().resources.get(path.getResourceId());
            if (resourceModel == null)
                return DiscoverResponse.notFound();

            Link resourceLink = LinkFormatHelper.getResourceDescription(getObjectModel().id,
                    path.getObjectInstanceId(), resourceModel, null);
            return DiscoverResponse.success(new Link[] { resourceLink });
        }
        return DiscoverResponse.badRequest(null);
    }

    @Override
    public synchronized ObserveResponse observe(ServerIdentity identity, ObserveRequest request) {
        LwM2mPath path = request.getPath();

        // observe is not supported for bootstrap
        if (identity.isLwm2mBootstrapServer())
            return ObserveResponse.methodNotAllowed();

        if (!identity.isSystem()) {
            // observe or read of the security object is forbidden
            if (id == LwM2mId.SECURITY)
                return ObserveResponse.notFound();

            // check if the resource is readable.
            if (path.isResource()) {
                ResourceModel resourceModel = objectModel.resources.get(path.getResourceId());
                if (resourceModel != null && !resourceModel.operations.isReadable())
                    return ObserveResponse.methodNotAllowed();
            }
        }
        return doObserve(identity, request);
    }

    protected ObserveResponse doObserve(ServerIdentity identity, ObserveRequest request) {
        ReadResponse readResponse = this.read(identity, new ReadRequest(request.getPath().toString()));
        return new ObserveResponse(readResponse.getCode(), readResponse.getContent(), null, null,
                   readResponse.getErrorMessage());
    }

    @Override
    public void setNotifySender(NotifySender sender) {
        notifySender = sender;
    }

    public NotifySender getNotifySender() {
        return notifySender;
    }
}
