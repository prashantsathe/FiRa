package com.android.fira;

import javacard.framework.JCSystem;

public class SessionManager {

    private byte[] mChannelAllocation;

    protected SessionManager() {
        mChannelAllocation = JCSystem.makeTransientByteArray(Constant.NU_LOGICAL_CHANNEL, JCSystem.CLEAR_ON_DESELECT);
    }
}
