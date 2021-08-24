package com.android.ber;

public class BerLinkList {
    private ListObj rootObj;
    private ListObj tailObj;
    private short size;

    public BerLinkList() {
        rootObj = tailObj = null;
        size = 0;
    }

    public void AddToTop(BerTlv tlv) {
        /* TODO: memory allocation */
        ListObj obj = new ListObj();
        obj.tlv = tlv;
        obj.nextPtr = null;

        if (rootObj == null) {
            rootObj = obj;
            tailObj = obj;
        } else {
            obj.nextPtr = tailObj;
            rootObj     = obj;
        }
        size++;
    }

    public void AddToBottom(BerTlv tlv) {
        /* TODO: memory allocation */
        ListObj obj = new ListObj();
        obj.tlv = tlv;
        obj.nextPtr = null;

        if (rootObj == null) {
            rootObj = obj;
            tailObj = obj;
        } else {
            tailObj.nextPtr = obj;
            tailObj         = obj;
        }
        size++;
    }

    public short SizeOfList() {
        return size;
    }

    private class ListObj {
        BerTlv tlv;
        ListObj nextPtr;
    }
}
