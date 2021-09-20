package com.android.fira.applet;


import javacard.framework.JCSystem;
import javacard.framework.*;

public class Repository {

    private byte[] mADFBuffer;
    private byte[] mApplicationDataStructure;
    private byte mOffsetCurrentADFBuffer;

    protected Repository() {
        mADFBuffer = JCSystem.makeTransientByteArray(Constant.ADF_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET);
        mApplicationDataStructure = JCSystem.makeTransientByteArray(Constant.ADF_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET);
        mOffsetCurrentADFBuffer = 0;
    }

    public byte[] getADFBuffer() {
        return mADFBuffer;
    }
    public short getADFBufferOffset() {
        return (short) (mOffsetCurrentADFBuffer * Constant.ADF_BUFFER_SIZE / 2);
    }
    public void setCurrentADF() {
        mOffsetCurrentADFBuffer = (byte) (mOffsetCurrentADFBuffer == 0 ? 1 : 0);
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
