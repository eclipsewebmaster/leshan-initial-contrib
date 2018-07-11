package org.eclipse.leshan.core.attributes;

import static org.junit.Assert.*;

import java.util.EnumSet;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class AttributeTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    
    @Test
    public void should_pick_correct_model() {
        Attribute verAttribute = new Attribute(Attribute.OBJECT_VERSION, "1.0");
        assertEquals("ver", verAttribute.getCoRELinkParam());
        assertEquals("1.0", verAttribute.getValue());
        assertTrue(verAttribute.canBeAssignedTo(AssignationLevel.OBJECT));
        assertFalse(verAttribute.isWritable());
    }
    
    @Test
    public void should_throw_on_invalid_value_type() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage(Attribute.OBJECT_VERSION);
        new Attribute(Attribute.OBJECT_VERSION, 123);
    }
}
