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
package com.android.javacard.FiraScTest;

import com.android.javacard.SecureChannels.FiraClientContext;

public class ADF extends FiraClientContext {

    public boolean isSelectAdfAllowed(byte[] buf, short index, short len) {
        // TODO Auto-generated method stub
        return false;
    }

    public short getKeySet(short kvn, byte[] buf, short bufOffset) {
        short index = bufOffset;

        // Default symmetric KeySet
        // TODO remove it
        buf[index++] = (byte) 0xB9; buf[index++] = (byte) 0x2E;
        buf[index++] = (byte) 0x80; buf[index++] = (byte) 0x01;

        // In "testFiRaSC" function we have used following KVNs
        // 5 for privacy kvn and 6 for SC kvn In FiRa sc1
        // 31 for privacy kvn and 32 for SC kvn In FiRa sc2 SYS
        // 33 for SC kvn In FiRa sc2 ASYS
        if (kvn == (short) 5) {
            buf[index++] = (byte) 0x81;
        } else if (kvn == (short) 6) {
            buf[index++] = (byte) 0x01;
        } else if (kvn == (short) 31) {
            buf[index++] = (byte) 0x82;
        } else if (kvn == (short) 32) {
            buf[index++] = (byte) 0x02;
        } else if (kvn == (short) 33) {
            buf[index++] = (byte) 0x02;
        } else {
            buf[index++] = (byte) 0x01;
        }

        buf[index++] = (byte) 0x82; buf[index++] = (byte) 0x01; buf[index++] = (byte) 0x01;
        buf[index++] = (byte) 0x83; buf[index++] = (byte) 0x01; buf[index++] = 0x01; /*KVN*/
        buf[index++] = (byte) 0x84; buf[index++] = (byte) 0x10;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x85; buf[index++] = (byte) 0x10;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;

        return (short) (index - bufOffset);
    }

    public byte getSelectedKvn(byte kvnType) {
        // TODO Auto-generated method stub
        return 0;
    }

    public short getPreSelectedAdf(byte[] oidBuf, short start) {
        // TODO Auto-generated method stub
        return 0;
    }

    public short getPendingEvent() {
        // TODO Auto-generated method stub
        return 0;
    }

    public void signal(short eventId) {
        // TODO Auto-generated method stub
    }

    public boolean selectAdf(byte[] oidBuf, short start, short len) {
        // TODO Auto-generated method stub
        return true;
    }

    public short getSelectedKvn(byte kvnType, byte[] buf, short bufOffset) {
        // TODO remove it
        // SYS sc1 keyset
        if (kvnType == 0x01) return 0;

        short index = bufOffset;

        buf[index++] = (byte) 0xB9; buf[index++] = (byte) 0x2E;
        buf[index++] = (byte) 0x80; buf[index++] = (byte) 0x01; buf[index++] = (byte) 0x01;
        buf[index++] = (byte) 0x82; buf[index++] = (byte) 0x01; buf[index++] = (byte) 0x01;
        buf[index++] = (byte) 0x83; buf[index++] = (byte) 0x01; buf[index++] = 0x01; /*KVN*/
        buf[index++] = (byte) 0x84; buf[index++] = (byte) 0x10;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x85; buf[index++] = (byte) 0x10;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;
        buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04; buf[index++] = (byte) 0x04;

        return (short) (index - bufOffset);
    }

    public short getCAPublicKey(byte kvn, byte[] buf, short index) {
        // TODO Auto-generated method stub
        return 0;
    }

    public short getSDSecretKey(byte[] buf, short index) {
        // TODO Auto-generated method stub
        return 0;
    }

    public short getSDCertificate(byte[] buf, short index) {
        // TODO Auto-generated method stub
        return 0;
    }
}