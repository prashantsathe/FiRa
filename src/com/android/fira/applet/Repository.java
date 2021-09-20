package com.android.fira.applet;


import javacard.framework.JCSystem;

public class Repository {

    private byte[] mADFBuffer;
    private byte[] mApplicationDataStructure;

    protected Repository() {
        mADFBuffer = JCSystem.makeTransientByteArray(Constant.ADF_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET);
        mApplicationDataStructure = JCSystem.makeTransientByteArray(Constant.ADF_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET);
    }

    public byte[] getADFBuffer() {
        return mADFBuffer;
    }
}
