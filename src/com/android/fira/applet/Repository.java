package com.android.fira.applet;

import javacard.framework.JCSystem;
import javacard.framework.*;

public class Repository {

    private byte[] mADFBuffer;
    private byte[] mApplicationDataStructure;
    private byte[] mAdfAllocation;

    protected Repository() {
        mADFBuffer = JCSystem.makeTransientByteArray(Constant.ADF_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET);
        mAdfAllocation = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

        mApplicationDataStructure = JCSystem.makeTransientByteArray(Constant.ADF_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET);
    }

    public byte[] getADFBuffers() {
        return mADFBuffer;
    }

    public short getFreeIndex() {
        byte temp = 1;

        for (short i = 0 ; i < 8 ; i++) {
            temp = (byte) (temp << i);

            if ((mAdfAllocation[0] & temp) != 1) {
                return i;
            }
        }
        return -1;
    }

    public short getFreeIndexOffset(short index) {
        return (short) (Constant.ADF_SIZE * index);
    }

    public void setADF(short index) {
        mAdfAllocation[0] |= (byte)(1 << index);
    }

    public boolean verifyAID(byte[] apduBuffer, short offset, short length) {
        // AID is consist of 16 bytes
        if (length > 16)
            return false;
        else {
            return 0 == Util.arrayCompare(apduBuffer, offset, mApplicationDataStructure, (short) 0, length);
        }
    }
}
