package com.android.ber;
import javacard.framework.JCSystem;

public class BerList {
    private Object elements[];
    private int listSize = 0;
    private static final short DEFAULT_CAPACITY = 30;

    public void AllocateBerList(short size) {
        elements = JCSystem.makeTransientObjectArray((short)size, JCSystem.CLEAR_ON_DESELECT);
    }

    public BerList() {
        AllocateBerList(DEFAULT_CAPACITY);
    }

    public BerList(short upperBound) {
        /* TODO:- any size limitation */
        AllocateBerList(upperBound);
    }

    public boolean add(BerTlv tlv) {
        if (elements.length <= (listSize - 1)) return false;

        elements[listSize++] = tlv;
        return true;
    }

    public BerTlv GetTlv(short index) {
        if (index >= listSize)
            return null;

        return (BerTlv) elements[index];
    }

    public int GetSize() { return listSize; }
    public int GetCapacity() { return elements.length; }

    public void reset() {
        listSize = 0;
        /* if memory management/free implementation available, free following memory */
        // free BTlvs;
        for (int i = 0; i < elements.length; i++) {
            // free BTlvs
        }
    }
}
