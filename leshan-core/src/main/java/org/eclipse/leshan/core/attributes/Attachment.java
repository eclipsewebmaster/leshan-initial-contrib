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
package org.eclipse.leshan.core.attributes;

/**
 * The attachment level of an LwM2m attribute.
 * 
 * This indicates the level (object, instance or resource) where an attribute can
 * be applied. E.g. the 'pmin' attribute can only be applied on the Resource level,
 * but it can be assigned on all levels. 'pmin' attributes that are assigned to
 * the object or instance level are then inherited by all resources that don't have
 * their own 'pmin' attribute. 
 */
public enum Attachment {
    OBJECT,
    INSTANCE,
    RESOURCE
}
