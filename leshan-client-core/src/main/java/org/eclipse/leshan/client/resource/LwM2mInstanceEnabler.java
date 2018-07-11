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
 *     Kai Hudalla (Bosch Software Innovations GmbH) - add documentation
 *     Achim Kraus (Bosch Software Innovations GmbH) - add reset() for 
 *                                                     REPLACE/UPDATE implementation
 *******************************************************************************/
package org.eclipse.leshan.client.resource;

import java.util.Collection;
import java.util.List;

import org.eclipse.leshan.Link;
import org.eclipse.leshan.ObserveSpec;
import org.eclipse.leshan.core.attributes.AttributeSet;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.request.WriteAttributesRequest;
import org.eclipse.leshan.core.response.DiscoverResponse;
import org.eclipse.leshan.core.response.ExecuteResponse;
import org.eclipse.leshan.core.response.ObserveResponse;
import org.eclipse.leshan.core.response.ReadResponse;
import org.eclipse.leshan.core.response.WriteAttributesResponse;
import org.eclipse.leshan.core.response.WriteResponse;

/**
 * A contract for managing a LWM2M object instance on a LWM2M client.
 * <p>
 * LWM2M clients should implement this interface for each LWM2M object type they support in order to take advantage of
 * automatic routing of requests from a LWM2M server to specific LWM2M object instances of that type and forwarding of
 * notifications to LWM2M servers observing resources on these instances.
 * </p>
 * <p>
 * Clients can register instances of this interface (representing the client's instances of a particular LWM2M object
 * type) using {@link ObjectsInitializer#setInstancesForObject(int, LwM2mInstanceEnabler...)} and then use
 * {@link ObjectsInitializer#create(int)} to create a {@link LwM2mObjectEnabler} instance for managing them.
 * </p>
 * <p>
 * Implementations of this interface should adhere to the definition of the implemented LWM2M Object type regarding
 * acceptable resource IDs for the <code>read, write</code> and <code>execute</code> methods.
 * </p>
 * 
 */
public interface LwM2mInstanceEnabler {

    /**
     * Returns a list of the resources id's that are available in this instance.
     * @return
     */
    Collection<Integer> getAvailableResourceIds();
    
    /**
     * Adds a callback handler that gets notified about changes to any of this LWM2M object instance's resources.
     * 
     * @param listener the handler to add, a <code>null</code> value is silently ignored
     */
    void addResourceChangedListener(ResourceChangedListener listener);

    /**
     * Stops a callback handler from getting notified about changes to any of this LWM2M object instance's resources.
     * 
     * @param listener the handler to remove, a <code>null</code> value is silently ignored
     */
    void removeResourceChangedListener(ResourceChangedListener listener);

    /**
     * Gets the current value of one of this LWM2M object instance's resources.
     * 
     * @param resourceId the ID of the resource to get the value of
     * @return the response object representing the outcome of the operation. An implementation should set the result's
     *         {@link ReadResponse#getCode() response code} to either reflect the success or reason for failure to
     *         retrieve the value.
     */
    ReadResponse read(int resourceId);

    /**
     * Sets the value of one of this LWM2M object instance's resources.
     * 
     * @param resourceid the ID of the resource to set the value for
     * @param value the value to set the resource to
     * @return the response object representing the outcome of the operation. An implementation should set the result's
     *         {@link WriteResponse#getCode() response code} to either reflect the success or reason for failure to set
     *         the value.
     */
    WriteResponse write(int resourceid, LwM2mResource value);

    /**
     * Executes the operation represented by one of this LWM2M object instance's resources.
     * 
     * @param resourceid the ID of the resource to set the value for
     * @param params the input parameters of the operation
     * @return the response object representing the outcome of the operation. An implementation should set the result's
     *         {@link ExecuteResponse#getCode() response code} to either reflect the success or reason for failure to
     *         execute the operation.
     */
    ExecuteResponse execute(int resourceid, String params);

    /**
     * Performs an observe register on one of this LWM2M object instance's resources.
     *
     * @param resourceid the ID of the resource to set the value for
     */
    ObserveResponse observe(int resourceid);

    /**
     * Performs a write of attributes on the instance level, e.g. affecting all resources that haven't specific
     * attributes themselves.
     * @return the response object representing the outcome of the operation.
     */
    WriteAttributesResponse writeInstanceAttributes(AttributeSet attributes);

    /**
     * Performs a write of attributes on the resource level.
     * @param observeSpec The NOTIFICATION class attributes that should be written to the resource
     * @return the response object representing the outcome of the operation.
     */
    WriteAttributesResponse writeResourceAttributes(int resourceId, AttributeSet attributes);

    /**
     * Performs a Discover on the instance. Link for the instance itself (including attached attributes) and links
     * for all instantiated resources (including their attributes) must be reported.
     * @param objectId The object id that this instance belongs to
     * @param objectAttributes object level attributes, that may contain instance or resource level attributes
     * @param instanceId The instance id of this instance
     * @return the response object representing the outcome of the request.
     */
    DiscoverResponse discoverInstance(int objectId, AttributeSet objectAttributes, int instanceId);

    /**
     * Performs Discover on a Resource. The resource link and all resource attributes on all levels should be included.
     * This means that if there are R attributes on the object or the instance, they must be included in the
     * returned Link.
     * @param objectId The object id that this resource belongs to
     * @param objectAttributes The attributes that are attached to the Object
     * @param instanceId The instance id that this resource belongs to
     * @return the response object containing all attributes that are applicable to this resource
     */
    DiscoverResponse discoverResource(int objectId, AttributeSet objectAttributes, int instanceId, int resourceId);
    
    /**
     * Reset the current value of one of this LWM2M object instance's resources. Only used for implementation of REPLACE
     * to cleanup none mandatory resources.
     * 
     * @param resourceId the ID of the resource to be reseted
     */
    void reset(int resourceId);
}
