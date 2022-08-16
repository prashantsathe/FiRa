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
package com.android.javacard.SecureChannels;

import static com.android.javacard.SecureChannels.FiraConstant.*;
import static com.android.javacard.SecureChannels.ScpConstant.*;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class FiraContext {

    // To avoid getter and setter making the members public
    public byte[] mBuf;

    // 'O_*' -> offset of the fields present in 'mBuf'
    public static final short O_SELECTED_OID = 0;
    public static final short O_SELECTED_OID_LEN = (short) (O_SELECTED_OID + MAX_OID_SIZE);
    // TODO: add variable length
    public static final short O_DEVICE_IDENTIFIER = (short) (O_SELECTED_OID_LEN + 1);
    public static final short O_KEY_PRI_ENC = (short) (O_DEVICE_IDENTIFIER + DEVICE_IDENTIFIER_SIZE); // TBD
    public static final short O_KEY_PUB_ENC = (short) (O_KEY_PRI_ENC + EC_SK_KEY_LENGTH); // TBD
    public static final short O_KSES_AUTHENC = (short) (O_KEY_PUB_ENC + EC_PK_KEY_LENGTH);
    public static final short O_EC_KEY_PRIV1 = (short) (O_KSES_AUTHENC + EC_SK_KEY_LENGTH);
    public static final short O_EC_KEY_PUB1 = (short) (O_EC_KEY_PRIV1 + EC_SK_KEY_LENGTH);
    public static final short O_EC_KEY_PRIV2 = (short) (O_EC_KEY_PUB1 + EC_PK_KEY_LENGTH);
    public static final short O_EC_KEY_PUB2 = (short) (O_EC_KEY_PRIV2 + EC_SK_KEY_LENGTH);
    public static final short O_EPHEMERAL_PUBKEY1 = (short) (O_EC_KEY_PUB2 + EC_PK_KEY_LENGTH);
    public static final short O_EPHEMERAL_PUBKEY2 = (short) (O_EPHEMERAL_PUBKEY1 + EC_PK_KEY_LENGTH);
    public static final short O_EPHEMERAL_PRIKEY1 = (short) (O_EPHEMERAL_PUBKEY2 + EC_PK_KEY_LENGTH);
    public static final short O_EPHEMERAL_PRIKEY2 = (short) (O_EPHEMERAL_PRIKEY1 + EC_SK_KEY_LENGTH);
    // is 'RandomData2', just following CSML convention
    public static final short O_RANDOM_DATA0 = (short) (O_EPHEMERAL_PRIKEY2 + EC_SK_KEY_LENGTH);
    public static final short O_RANDOM_DATA1 = (short) (O_RANDOM_DATA0 + BlOCK_16BYTES);
    public static final short O_RANDOM_IV = (short) (O_RANDOM_DATA1 + BlOCK_16BYTES);
    public static final short O_RANDOM_IFD = (short) (O_RANDOM_IV + BlOCK_16BYTES);
    public static final short O_KIFD = (short) (O_RANDOM_IFD + BlOCK_16BYTES);
    public static final short O_RANDOM_ICC = (short) (O_KIFD + BlOCK_16BYTES);
    public static final short O_CRYPTOGRAM2 = (short) (O_RANDOM_ICC + BlOCK_16BYTES);
    public static final short O_CHALLENGE1 = (short) (O_CRYPTOGRAM2 + BlOCK_16BYTES);
    public static final short O_CHALLENGE2 = (short) (O_CHALLENGE1 + BlOCK_16BYTES);
    public static final short O_P2 = (short) (O_CHALLENGE2 + BlOCK_16BYTES);
    public static final short O_SELECTION_INDEX = (short) (O_P2 + 1);
    public static final short O_SECURITY_LEVEL = (short) (O_SELECTION_INDEX + 1);
    public static final short O_RDS_FLAG = (short) (O_SECURITY_LEVEL + 1);
    public static final short O_UWB_SESSIONKEY = (short) (O_RDS_FLAG + 2);
    public static final short O_UWB_SESSIONID = (short) (O_UWB_SESSIONKEY + BlOCK_16BYTES);
    public static final short O_SC1_TAGNUMBER = (short) (O_UWB_SESSIONID + UWB_SESSION_ID_SIZE);
    private static final short O_OCCUPIED = (short) (O_SC1_TAGNUMBER + 2);
    public static final short O_SCP_STATUS = (short) (O_OCCUPIED + 1);
    public static final short O_ROLE = (short) (O_SCP_STATUS + 1);
    public static final short O_STATE = (short) (O_ROLE + 1);
    public static final short O_SC_KVN = (short) (O_STATE + 1);
    public static final short O_PRIV_KVN = (short) (O_SC_KVN + 2);
    public static final short O_AUTH_METHOD = (short) (O_PRIV_KVN + 2);
    public static final short O_BASE_KEYSET_SELECTED_KVN = (short) (O_AUTH_METHOD + 1);
    public static final short O_PRIVACY_KEYSET_SELECTED_KVN = (short) (O_BASE_KEYSET_SELECTED_KVN + 1);
    public static final short O_SC_KEYSET_SELECTED_KVN = (short) (O_PRIVACY_KEYSET_SELECTED_KVN + 1);
    public static final short O_UWB_ROOT_KEYSET_SELECTED_KVN = (short) (O_SC_KEYSET_SELECTED_KVN + 1);

    public FiraContext() {

        mBuf = JCSystem.makeTransientByteArray((short) (O_UWB_ROOT_KEYSET_SELECTED_KVN + 1),
                JCSystem.CLEAR_ON_RESET);
        RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mBuf, O_DEVICE_IDENTIFIER,
                DEVICE_IDENTIFIER_SIZE);

        mBuf[O_SECURITY_LEVEL] = NO_SECURITY_LEVEL;
        mBuf[O_BASE_KEYSET_SELECTED_KVN] = INVALID_VALUE;
        mBuf[O_PRIVACY_KEYSET_SELECTED_KVN] = INVALID_VALUE;
        mBuf[O_SC_KEYSET_SELECTED_KVN] = INVALID_VALUE;
        mBuf[O_UWB_ROOT_KEYSET_SELECTED_KVN] = INVALID_VALUE;

        setRole(FiraConstant.RESPONDER);
        setState(FiraConstant.UNSECURE);

        /* // default key / dummy data for SC2 testing
        {
        Util.arrayFillNonAtomic(mBuf, O_DEVICE_IDENTIFIER, DEVICE_IDENTIFIER_SIZE, (byte) 0x02);
        Util.arrayFillNonAtomic(mBuf, O_EC_KEY_PRIV1, EC_SK_KEY_LENGTH, C_04);
        Util.arrayFillNonAtomic(mBuf, O_EC_KEY_PRIV2, EC_SK_KEY_LENGTH, C_04);

        //SK.SD.ECKA  0404040404040404040404040404040404040404040404040404040404040404
        //PKX.SD.ECKA 73103E C30B3CCF 57DAAE08 E93534AE F144A359 40CF6BBB A12A0CF7 CBD5D65A 64
        //PKY.SD.ECKA D82C8C99 E9D3C45F 9245BA9B 27982C9A EA8EC1DB 94B19C44 795942C0 EB22AA32
        Util.arrayFillNonAtomic(mBuf, O_KEY_PRI_ENC, EC_SK_KEY_LENGTH, C_04);
        short index = O_KEY_PUB_ENC;
        mBuf[index++] = 0x04;
        mBuf[index++] = 0x73; mBuf[index++] = 0x10; mBuf[index++] = 0x3E;
        mBuf[index++] = (byte) 0xC3; mBuf[index++] = 0x0B; mBuf[index++] = 0x3C; mBuf[index++] = (byte) 0xCF;
        mBuf[index++] = 0x57; mBuf[index++] = (byte) 0xDA; mBuf[index++] = (byte) 0xAE; mBuf[index++] = 0x08;
        mBuf[index++] = (byte) 0xE9; mBuf[index++] = 0x35; mBuf[index++] = 0x34; mBuf[index++] = (byte) 0xAE;
        mBuf[index++] = (byte) 0xF1; mBuf[index++] = 0x44; mBuf[index++] = (byte) 0xA3; mBuf[index++] = 0x59;
        mBuf[index++] = 0x40; mBuf[index++] = (byte) 0xCF; mBuf[index++] = 0x6B; mBuf[index++] = (byte) 0xBB;
        mBuf[index++] = (byte) 0xA1; mBuf[index++] = 0x2A; mBuf[index++] = 0x0C; mBuf[index++] = (byte) 0xF7;
        mBuf[index++] = (byte) 0xCB; mBuf[index++] = (byte) 0xD5; mBuf[index++] = (byte) 0xD6; mBuf[index++] = 0x5A;
        mBuf[index++] = 0x64;
        mBuf[index++] = (byte) 0xD8; mBuf[index++] = 0x2C; mBuf[index++] = (byte) 0x8C; mBuf[index++] = (byte) 0x99;
        mBuf[index++] = (byte) 0xE9; mBuf[index++] = (byte) 0xD3; mBuf[index++] = (byte) 0xC4; mBuf[index++] = 0x5F;
        mBuf[index++] = (byte) 0x92; mBuf[index++] = 0x45; mBuf[index++] = (byte) 0xBA; mBuf[index++] = (byte) 0x9B;
        mBuf[index++] = 0x27; mBuf[index++] = (byte) 0x98; mBuf[index++] = 0x2C; mBuf[index++] = (byte) 0x9A;
        mBuf[index++] = (byte) 0xEA; mBuf[index++] = (byte) 0x8E; mBuf[index++] = (byte) 0xC1; mBuf[index++] = (byte) 0xDB;
        mBuf[index++] = (byte) 0x94; mBuf[index++] = (byte) 0xB1; mBuf[index++] = (byte) 0x9C; mBuf[index++] = 0x44;
        mBuf[index++] = 0x79; mBuf[index++] = 0x59; mBuf[index++] = 0x42; mBuf[index++] = (byte) 0xC0;
        mBuf[index++] = (byte) 0xEB; mBuf[index++] = 0x22; mBuf[index++] = (byte) 0xAA; mBuf[index++] = 0x32;
        }
        */
    }

    public boolean isFree() {
        return mBuf[O_OCCUPIED] == 1 ? false : true;
    }

    public void setOccupied(boolean val) {
        mBuf[O_OCCUPIED] = (byte) (val == true ? 1 : 0);
    }

    public void resetContext() {
        Util.arrayFillNonAtomic(mBuf, (short) 0, 
                (short) mBuf.length, (byte) 0x00);

        mBuf[O_ROLE] = RESPONDER;
        mBuf[O_STATE] = UNSECURE;
        mBuf[O_BASE_KEYSET_SELECTED_KVN] = INVALID_VALUE;
        mBuf[O_PRIVACY_KEYSET_SELECTED_KVN] = INVALID_VALUE;
        mBuf[O_SC_KEYSET_SELECTED_KVN] = INVALID_VALUE;
        mBuf[O_UWB_ROOT_KEYSET_SELECTED_KVN] = INVALID_VALUE;
    }

    public void setState(byte state) {
        mBuf[O_STATE] = state;
    }

    public byte getState(){
        return mBuf[O_STATE];
    }

    public void setRole(byte role) {
        mBuf[O_ROLE] = role;
    }

    public boolean isInitiator() {
        return mBuf[O_ROLE] == FiraConstant.INITIATOR;
    }

    public void setOrResetContext(boolean val) {
        mBuf[O_OCCUPIED] = (byte) (val == true ? 1 : 0);
    }
}
