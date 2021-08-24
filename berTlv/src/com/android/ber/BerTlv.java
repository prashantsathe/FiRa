package com.android.ber;

public class BerTlv {
    /* Avoiding any method to access/set below members */
    public byte[] berTagPtr;
    public byte[] berLengthPtr;
    public byte[] berValuePtr;
    public BerLinkList berLinkList;

    public short berLength; // TODO: remove this
    public short offset;    // TODO: remove this This is an offset in the buffer()
}
