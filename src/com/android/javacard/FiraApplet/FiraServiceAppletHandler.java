/*
 * Copyright(C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.FiraApplet;

import com.android.javacard.FiRaServiceApplet.FiRaServiceApplet;
import javacard.framework.AID;
import javacard.framework.JCSystem;

public class FiraServiceAppletHandler {

    private static final byte SERVICE_ID = (byte) 0xFA;
    private final boolean[] mReserved;
    private FiRaServiceApplet mAppletRef;
    private AID appletId;

    public FiraServiceAppletHandler(byte[] buf, short inputStart, byte inputLen) {
        appletId = new AID(buf, inputStart, inputLen);
        mReserved = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mReserved[0] = false;
    }

    public void delete() {
        appletId = null;
        mAppletRef = null;
        JCSystem.requestObjectDeletion();
    }

    public short init(byte[] oid, short index, short len) {
        FiRaServiceApplet appletRef = (FiRaServiceApplet) JCSystem
                .getAppletShareableInterfaceObject(appletId, SERVICE_ID);
        len = appletRef.setCallerOid(oid, index, len, null, (short) 0);
        mReserved[0] = true;
        return len;
    }

    public boolean isReserved() {
        return mReserved[0];
    }

    public void cleanUp() {
        mReserved[0] = false;
        FiRaServiceApplet appletRef = (FiRaServiceApplet) JCSystem
                .getAppletShareableInterfaceObject(appletId, SERVICE_ID);
        appletRef.processFiRaServiceCleanup();
    }

    public short getAppletId(byte[] buf, short index) {
        return appletId.getBytes(buf, index);
    }

    public boolean isAppletIdEquals(byte[] buf, short index, byte len) {
        return appletId.equals(buf, index, len);
    }

    public short dispatch(byte[] buf, short cmdIndex, short cmdLen, byte[] outBuf, short outIndex) {
        FiRaServiceApplet appletRef = (FiRaServiceApplet) JCSystem
                .getAppletShareableInterfaceObject(appletId, SERVICE_ID);
        return appletRef.processFiRaServiceCommand(buf, cmdIndex, cmdLen, outBuf, outIndex);
    }
}
