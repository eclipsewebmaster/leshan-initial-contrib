package org.eclipse.leshan.client.resource;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.eclipse.leshan.Link;
import org.eclipse.leshan.ResponseCode;
import org.eclipse.leshan.client.request.ServerIdentity;
import org.eclipse.leshan.core.attributes.Attribute;
import org.eclipse.leshan.core.attributes.AttributeSet;
import org.eclipse.leshan.core.model.ObjectModel;
import org.eclipse.leshan.core.request.DiscoverRequest;
import org.eclipse.leshan.core.response.DiscoverResponse;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

public class ObjectEnablerTest {

    private static final int OBJECT_ID = 3;

    @Mock
    private ObjectModel objectModel;
    @Mock
    private AttributeSet attributeSet;
    @Mock
    private LwM2mInstanceEnablerFactory instanceFactory;
    @Mock
    private BaseInstanceEnabler instanceEnabler01;
    @Mock
    private BaseInstanceEnabler instanceEnabler02;

    private ObjectEnabler sut;

    @Before
    public void setup() {
        initMocks(this);

        // Two instances
        Map<Integer, LwM2mInstanceEnabler> instances = new HashMap<>();
        instances.put(0, instanceEnabler01);
        instances.put(1, instanceEnabler02);

        sut = new ObjectEnabler(OBJECT_ID, objectModel, instances, attributeSet, instanceFactory);
    }

    @Test
    public void should_discover_object_level() {
        Map<String, Object> objectAttributeMap = new LinkedHashMap<>();
        objectAttributeMap.put("ver", "1.5");
        objectAttributeMap.put("pmin", 123L);
        objectAttributeMap.put("pmax", 345L);
        when(attributeSet.getMap()).thenReturn(objectAttributeMap);

        when(instanceEnabler01.discoverInstance(eq(OBJECT_ID), any(AttributeSet.class), eq(0)))
                .thenReturn(DiscoverResponse.success(
                        new Link[] {
                                new Link("/3/0", new AttributeSet(Attribute.create("pmin", 5L))),
                                new Link("/3/0/0", new AttributeSet(Attribute.create("pmin", 10L)))
                        }));
        when(instanceEnabler02.discoverInstance(eq(OBJECT_ID), any(AttributeSet.class), eq(1))).thenReturn(
                DiscoverResponse.success(new Link[] {
                        new Link("/3/1", new AttributeSet(Attribute.create("pmin", 5L))),
                        new Link("/3/1/4", new AttributeSet(Attribute.create("pmin", 10L)))
                }));

        DiscoverResponse response = sut.discover(ServerIdentity.SYSTEM, new DiscoverRequest(3));
        Link[] links = response.getObjectLinks();
        assertEquals(ResponseCode.CONTENT, response.getCode());
        assertEquals(5, links.length);
        assertTrue(links[0].toString().startsWith("</3>"));
        // No guaranteed order of the attributes
        assertTrue(links[0].toString().contains("pmin=123"));
        assertTrue(links[0].toString().contains("pmax=345"));
        assertTrue(links[0].toString().contains("ver=\"1.5\""));
        assertEquals("</3/0>", links[1].toString());
        assertEquals("</3/0/0>", links[2].toString());
        assertEquals("</3/1>", links[3].toString());
        assertEquals("</3/1/4>", links[4].toString());
    }

    @Test
    public void should_discover_instance_level() {
        when(instanceEnabler02.discoverInstance(eq(OBJECT_ID), any(AttributeSet.class), eq(1))).thenReturn(DiscoverResponse.success(
                new Link[] {
                new Link("/3/1", new AttributeSet(Attribute.create("pmin", 5L))),
                new Link("/3/1/4", new AttributeSet(Attribute.create("pmin", 10L)))
        }));

        DiscoverResponse response = sut.discover(ServerIdentity.SYSTEM, new DiscoverRequest(3, 1));
        Link[] links = response.getObjectLinks();
        assertEquals(ResponseCode.CONTENT, response.getCode());
        assertEquals(2, links.length);
        assertEquals("</3/1>;pmin=5", links[0].toString());
        assertEquals("</3/1/4>;pmin=10", links[1].toString());
    }

    @Test
    public void should_discover_resource_level() {
        when(instanceEnabler02.discoverResource(eq(OBJECT_ID), any(AttributeSet.class), eq(1), eq(4))).thenReturn(
                DiscoverResponse.success(new Link[] {
                        new Link("/3/1/4", new AttributeSet(Attribute.create("pmin", 5L), Attribute.create("pmax", 345L)))
                }));

        DiscoverResponse response = sut.discover(ServerIdentity.SYSTEM, new DiscoverRequest(3, 1, 4));
        Link[] links = response.getObjectLinks();
        assertEquals(ResponseCode.CONTENT, response.getCode());
        assertEquals(1, links.length);
        assertTrue(links[0].toString().startsWith("</3/1/4>"));
        // No guaranteed order of the attributes
        assertTrue(links[0].toString().contains("pmin=5")); // Inherited from instance level
        assertTrue(links[0].toString().contains("pmax=345")); // Inherited from object level
    }

    @Test
    public void should_return_not_found_instance() {
        DiscoverResponse response = sut.discover(ServerIdentity.SYSTEM, new DiscoverRequest(3, 2));
        assertEquals(ResponseCode.NOT_FOUND, response.getCode());
    }

    @Test
    public void should_return_not_found_resource() {
        when(instanceEnabler02.discoverResource(eq(OBJECT_ID), any(AttributeSet.class), eq(1), eq(5))).thenReturn(DiscoverResponse.notFound());
       
        DiscoverResponse response = sut.discover(ServerIdentity.SYSTEM, new DiscoverRequest(3, 1, 5));
        assertEquals(ResponseCode.NOT_FOUND, response.getCode());
    }
}
