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

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.eclipse.leshan.util.Validate;

import java.util.Set;

/**
 * Represents an LwM2m attribute that can be attached to an object, instance or resource.
 * 
 * The {@link Attachment} level of the attribute indicates where it can be applied, e.g.
 * the 'pmin' attribute is only applicable to resources, but it can be assigned on all levels
 * and then inherited by underlying resources.
 */
public class Attribute {
    
    public static final String DIMENSION = "dim";
    public static final String OBJECT_VERSION = "ver";
    public static final String MINIMUM_PERIOD = "pmin";
    public static final String MAXIMUM_PERIOD = "pmax";
    public static final String GREATER_THAN = "gt";
    public static final String LESSER_THAN = "lt";
    public static final String STEP = "st";
    
    /**
     * Metadata container for LwM2m attributes
     */
    private static class AttributeModel {
        private final String coRELinkParam;
        private final Attachment attachment;
        private final Set<AssignationLevel> assignationLevels;
        private final AccessMode accessMode;
        private final Class<?> valueClass;

        private AttributeModel(String coRELinkParam, Attachment attachment, Set<AssignationLevel> assignationLevels,
                AccessMode accessMode, Class<?> valueClass) {
            this.coRELinkParam = coRELinkParam;
            this.attachment = attachment;
            this.assignationLevels = assignationLevels;
            this.accessMode = accessMode;
            this.valueClass = valueClass;
        }
    }
    
    private static Map<String, AttributeModel> modelMap;
    
    static {
        modelMap = new HashMap<>();
        modelMap.put(DIMENSION, new Attribute.AttributeModel(DIMENSION, Attachment.RESOURCE, EnumSet.of(AssignationLevel.RESOURCE),
                AccessMode.R, Long.class));
        modelMap.put(OBJECT_VERSION, new Attribute.AttributeModel(OBJECT_VERSION, Attachment.OBJECT, EnumSet.of(AssignationLevel.OBJECT),
                AccessMode.R, String.class));
        modelMap.put(MINIMUM_PERIOD, new Attribute.AttributeModel(MINIMUM_PERIOD, Attachment.RESOURCE,
                EnumSet.of(AssignationLevel.OBJECT, AssignationLevel.INSTANCE, AssignationLevel.RESOURCE),
                AccessMode.RW, Long.class));
        modelMap.put(MAXIMUM_PERIOD, new Attribute.AttributeModel(MAXIMUM_PERIOD, Attachment.RESOURCE,
                EnumSet.of(AssignationLevel.OBJECT, AssignationLevel.INSTANCE, AssignationLevel.RESOURCE),
                AccessMode.RW, Long.class));
        modelMap.put(GREATER_THAN, new AttributeModel(GREATER_THAN, Attachment.RESOURCE,
                EnumSet.of(AssignationLevel.RESOURCE),  AccessMode.RW,  Double.class));
        modelMap.put(LESSER_THAN, new AttributeModel(LESSER_THAN, Attachment.RESOURCE,
                EnumSet.of(AssignationLevel.RESOURCE),  AccessMode.RW,  Double.class));
        modelMap.put(STEP, new AttributeModel(STEP, Attachment.RESOURCE,
                EnumSet.of(AssignationLevel.RESOURCE),  AccessMode.RW,  Double.class));
    }

    private final AttributeModel model;
    private final Object value;
    
    public Attribute(String coRELinkParam, Object value) {
        Validate.notEmpty(coRELinkParam);
        this.model = modelMap.get(coRELinkParam);
        if (model == null) {
            throw new IllegalArgumentException(String.format("Unsupported attribute '%s'", coRELinkParam));
        }
        this.value = ensureMatchingValue(model, value);
    }

    public static Attribute create(String coRELinkParam, Object value) {
        return new Attribute(coRELinkParam, value);
    }

    /**
     * Ensures that a provided attribute value matches the attribute value type, including trying
     * to perform a correct conversion if the value is a string, e.g.
     * @return the converted or original value
     */
    private Object ensureMatchingValue(AttributeModel model, Object value) {
        // Ensure that the attribute value has the correct type
        // If the value is a string, we make an attempt to convert it
        Class<?> expectedClass = model.valueClass;
        if (!expectedClass.equals(value.getClass()) && value instanceof String) {
            if (expectedClass.equals(Long.class)) {
                return Long.parseLong(value.toString());
            } else if (expectedClass.equals(Double.class)) {
                return Double.parseDouble(value.toString());
            }
        } else if (!this.model.valueClass.equals(value.getClass())) {
            throw new IllegalArgumentException(String.format("Attribute '%s' must have a value of type %s",
                    model.coRELinkParam, model.valueClass.getSimpleName()));
        }
        return value;
    }
    
    public String getCoRELinkParam() {
        return model.coRELinkParam;
    }

    public Object getValue() {
        return value;
    }

    public Attachment getAttachment() {
        return model.attachment;
    }
    
    public boolean isWritable() {
        return model.accessMode == AccessMode.W || model.accessMode == AccessMode.RW;
    }
    
    public boolean canBeAssignedTo(AssignationLevel assignationLevel) {
        return model.assignationLevels.contains(assignationLevel);
    }
}
