package com.android.javacard.SecureChannels;

import static com.android.javacard.SecureChannels.FiraConstant.*;
import static com.android.javacard.SecureChannels.ScpConstant.*;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class FiraContext {

    // To avoid getter and setter making the members public
    public byte[] mContextBuffer;

    public static final short AUTHENTICATE_METHOD_OFFSET = 0;
    public static final short SELECTED_OID_OFFSET = (short) (AUTHENTICATE_METHOD_OFFSET + 1);
    public static final short SELECTED_OID_LENGTH_OFFSET = (short) (SELECTED_OID_OFFSET + MAX_OID_SIZE);
    // TODO: add variable length
    public static final short DEVICE_IDENTIFIER_OFFSET = (short) (SELECTED_OID_LENGTH_OFFSET + 1);
    public static final short KEY_PRI_ENC_OFFSET = (short) (DEVICE_IDENTIFIER_OFFSET + DEVICE_IDENTIFIER_SIZE); // TBD
    public static final short KEY_PUB_ENC_OFFSET = (short) (KEY_PRI_ENC_OFFSET + EC_SK_KEY_LENGTH); // TBD
    public static final short KSES_AUTHENC_OFFSET = (short) (KEY_PUB_ENC_OFFSET + EC_PK_KEY_LENGTH);
    public static final short EC_KEY_PRIV1_OFFSET = (short) (KSES_AUTHENC_OFFSET + EC_SK_KEY_LENGTH);
    public static final short EC_KEY_PUB1_OFFSET = (short) (EC_KEY_PRIV1_OFFSET + EC_SK_KEY_LENGTH);
    public static final short EC_KEY_PRIV2_OFFSET = (short) (EC_KEY_PUB1_OFFSET + EC_PK_KEY_LENGTH);
    public static final short EC_KEY_PUB2_OFFSET = (short) (EC_KEY_PRIV2_OFFSET + EC_SK_KEY_LENGTH);
    public static final short EPHEMERAL_PUBKEY1_OFFSET = (short) (EC_KEY_PUB2_OFFSET + EC_PK_KEY_LENGTH);
    public static final short EPHEMERAL_PUBKEY2_OFFSET = (short) (EPHEMERAL_PUBKEY1_OFFSET + EC_PK_KEY_LENGTH);
    public static final short EPHEMERAL_PRIKEY1_OFFSET = (short) (EPHEMERAL_PUBKEY2_OFFSET + EC_PK_KEY_LENGTH);
    public static final short EPHEMERAL_PRIKEY2_OFFSET = (short) (EPHEMERAL_PRIKEY1_OFFSET + EC_SK_KEY_LENGTH);
    public static final short RANDOM_DATA0_OFFSET = (short) (EPHEMERAL_PRIKEY2_OFFSET + EC_SK_KEY_LENGTH); // is 'RandomData2', just following CSML convention
    public static final short RANDOM_DATA1_OFFSET = (short) (RANDOM_DATA0_OFFSET + BlOCK_16BYTES);
    public static final short RANDOM_IV_OFFSET = (short) (RANDOM_DATA1_OFFSET + BlOCK_16BYTES);
    public static final short RANDOM_IFD_OFFSET = (short) (RANDOM_IV_OFFSET + BlOCK_16BYTES);
    public static final short KIFD_OFFSET = (short) (RANDOM_IFD_OFFSET + BlOCK_16BYTES);
    public static final short RANDOM_ICC_OFFSET = (short) (KIFD_OFFSET + BlOCK_16BYTES);
    public static final short CRYPTOGRAM2_OFFSET = (short) (RANDOM_ICC_OFFSET + BlOCK_16BYTES);
    public static final short CHALLENGE1_OFFSET = (short) (CRYPTOGRAM2_OFFSET + BlOCK_16BYTES);
    public static final short CHALLENGE2_OFFSET = (short) (CHALLENGE1_OFFSET + BlOCK_16BYTES);
    public static final short P2_OFFSET = (short) (CHALLENGE2_OFFSET + BlOCK_16BYTES);
    public static final short SELECTION_INDEX_OFFSET = (short) (P2_OFFSET + 1);
    public static final short SECURITY_LEVEL_OFFSET = (short) (SELECTION_INDEX_OFFSET + 1);
    public static final short RDS_FLAG_OFFSET = (short) (SECURITY_LEVEL_OFFSET + 1);
    public static final short UWB_SESSIONKEY_OFFSET = (short) (RDS_FLAG_OFFSET + 2);
    public static final short UWB_SESSIONID_OFFSET = (short) (UWB_SESSIONKEY_OFFSET + BlOCK_16BYTES);
    public static final short SC1_TAGNUMBER_OFFSET = (short) (UWB_SESSIONID_OFFSET + UWB_SESSION_ID_SIZE);
    private static final short OCCUPIED_OFFSET = (short) (SC1_TAGNUMBER_OFFSET + 2);
    public static final short SCP_STATUS_OFFSET = (short) (OCCUPIED_OFFSET + 1);
    public static final short ROLE_OFFSET = (short) (SCP_STATUS_OFFSET + 1);
    public static final short STATE_OFFSET = (short) (ROLE_OFFSET + 1);
    public static final short SC_KVN_OFFSET = (short) (STATE_OFFSET + 1);
    public static final short PRIV_KVN_OFFSET = (short) (SC_KVN_OFFSET + 2);
    public static final short AUTH_METHOD_OFFSET = (short) (PRIV_KVN_OFFSET + 2);
    public static final short BASE_KEYSET_SELECTED_KVN_OFFSET = (short) (AUTH_METHOD_OFFSET + 1);
    public static final short PRIVACY_KEYSET_SELECTED_KVN_OFFSET = (short) (BASE_KEYSET_SELECTED_KVN_OFFSET + 1);
    public static final short SC_KEYSET_SELECTED_KVN_OFFSET = (short) (PRIVACY_KEYSET_SELECTED_KVN_OFFSET + 1);
    public static final short UWB_ROOT_KEYSET_SELECTED_KVN_OFFSET = (short) (SC_KEYSET_SELECTED_KVN_OFFSET + 1);

    public FiraContext() {

        mContextBuffer = JCSystem.makeTransientByteArray((short) (UWB_ROOT_KEYSET_SELECTED_KVN_OFFSET + 1), JCSystem.CLEAR_ON_RESET);

        RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mContextBuffer, DEVICE_IDENTIFIER_OFFSET, DEVICE_IDENTIFIER_SIZE);
        mContextBuffer[SECURITY_LEVEL_OFFSET] = NO_SECURITY_LEVEL;

        mContextBuffer[BASE_KEYSET_SELECTED_KVN_OFFSET] = INVALID_VALUE;
        mContextBuffer[PRIVACY_KEYSET_SELECTED_KVN_OFFSET] = INVALID_VALUE;
        mContextBuffer[SC_KEYSET_SELECTED_KVN_OFFSET] = INVALID_VALUE;
        mContextBuffer[UWB_ROOT_KEYSET_SELECTED_KVN_OFFSET] = INVALID_VALUE;

        setRole(FiraConstant.RESPONDER);
        setState(FiraConstant.UNSECURE);

        // default key / dummy data / TODO: remove it
        {
        Util.arrayFillNonAtomic(mContextBuffer, DEVICE_IDENTIFIER_OFFSET, DEVICE_IDENTIFIER_SIZE, (byte) 0x02);
        Util.arrayFillNonAtomic(mContextBuffer, EC_KEY_PRIV1_OFFSET, EC_SK_KEY_LENGTH, C_04);
        Util.arrayFillNonAtomic(mContextBuffer, EC_KEY_PRIV2_OFFSET, EC_SK_KEY_LENGTH, C_04);

        //SK.SD.ECKA  0404040404040404040404040404040404040404040404040404040404040404
        //PKX.SD.ECKA 73103E C30B3CCF 57DAAE08 E93534AE F144A359 40CF6BBB A12A0CF7 CBD5D65A 64
        //PKY.SD.ECKA D82C8C99 E9D3C45F 9245BA9B 27982C9A EA8EC1DB 94B19C44 795942C0 EB22AA32
        Util.arrayFillNonAtomic(mContextBuffer, KEY_PRI_ENC_OFFSET, EC_SK_KEY_LENGTH, C_04);
        short index = KEY_PUB_ENC_OFFSET;
        mContextBuffer[index++] = 0x04;
        mContextBuffer[index++] = 0x73; mContextBuffer[index++] = 0x10; mContextBuffer[index++] = 0x3E;
        mContextBuffer[index++] = (byte) 0xC3; mContextBuffer[index++] = 0x0B; mContextBuffer[index++] = 0x3C; mContextBuffer[index++] = (byte) 0xCF;
        mContextBuffer[index++] = 0x57; mContextBuffer[index++] = (byte) 0xDA; mContextBuffer[index++] = (byte) 0xAE; mContextBuffer[index++] = 0x08;
        mContextBuffer[index++] = (byte) 0xE9; mContextBuffer[index++] = 0x35; mContextBuffer[index++] = 0x34; mContextBuffer[index++] = (byte) 0xAE;
        mContextBuffer[index++] = (byte) 0xF1; mContextBuffer[index++] = 0x44; mContextBuffer[index++] = (byte) 0xA3; mContextBuffer[index++] = 0x59;
        mContextBuffer[index++] = 0x40; mContextBuffer[index++] = (byte) 0xCF; mContextBuffer[index++] = 0x6B; mContextBuffer[index++] = (byte) 0xBB;
        mContextBuffer[index++] = (byte) 0xA1; mContextBuffer[index++] = 0x2A; mContextBuffer[index++] = 0x0C; mContextBuffer[index++] = (byte) 0xF7;
        mContextBuffer[index++] = (byte) 0xCB; mContextBuffer[index++] = (byte) 0xD5; mContextBuffer[index++] = (byte) 0xD6; mContextBuffer[index++] = 0x5A;
        mContextBuffer[index++] = 0x64;
        mContextBuffer[index++] = (byte) 0xD8; mContextBuffer[index++] = 0x2C; mContextBuffer[index++] = (byte) 0x8C; mContextBuffer[index++] = (byte) 0x99;
        mContextBuffer[index++] = (byte) 0xE9; mContextBuffer[index++] = (byte) 0xD3; mContextBuffer[index++] = (byte) 0xC4; mContextBuffer[index++] = 0x5F;
        mContextBuffer[index++] = (byte) 0x92; mContextBuffer[index++] = 0x45; mContextBuffer[index++] = (byte) 0xBA; mContextBuffer[index++] = (byte) 0x9B;
        mContextBuffer[index++] = 0x27; mContextBuffer[index++] = (byte) 0x98; mContextBuffer[index++] = 0x2C; mContextBuffer[index++] = (byte) 0x9A;
        mContextBuffer[index++] = (byte) 0xEA; mContextBuffer[index++] = (byte) 0x8E; mContextBuffer[index++] = (byte) 0xC1; mContextBuffer[index++] = (byte) 0xDB;
        mContextBuffer[index++] = (byte) 0x94; mContextBuffer[index++] = (byte) 0xB1; mContextBuffer[index++] = (byte) 0x9C; mContextBuffer[index++] = 0x44;
        mContextBuffer[index++] = 0x79; mContextBuffer[index++] = 0x59; mContextBuffer[index++] = 0x42; mContextBuffer[index++] = (byte) 0xC0;
        mContextBuffer[index++] = (byte) 0xEB; mContextBuffer[index++] = 0x22; mContextBuffer[index++] = (byte) 0xAA; mContextBuffer[index++] = 0x32;
        }
    }

    public boolean isFree() {
        return mContextBuffer[OCCUPIED_OFFSET] == 1 ? false : true;
    }

    public void setOccupied(boolean val) {
        mContextBuffer[OCCUPIED_OFFSET] = (byte) (val == true ? 1 : 0);
    }

    public void resetContext() {
        Util.arrayFillNonAtomic(mContextBuffer, (short) 0, 
                (short) mContextBuffer.length, (byte) 0x00);

        mContextBuffer[ROLE_OFFSET] = RESPONDER;
        mContextBuffer[STATE_OFFSET] = UNSECURE;
        mContextBuffer[BASE_KEYSET_SELECTED_KVN_OFFSET] = INVALID_VALUE;
        mContextBuffer[PRIVACY_KEYSET_SELECTED_KVN_OFFSET] = INVALID_VALUE;
        mContextBuffer[SC_KEYSET_SELECTED_KVN_OFFSET] = INVALID_VALUE;
        mContextBuffer[UWB_ROOT_KEYSET_SELECTED_KVN_OFFSET] = INVALID_VALUE;
    }

    public void setState(byte state) {
        mContextBuffer[STATE_OFFSET] = state;
    }

    public byte getState(){
        return mContextBuffer[STATE_OFFSET];
    }

    public void setRole(byte role) {
        mContextBuffer[ROLE_OFFSET] = role;
    }

    public boolean isInitiator() {
        return mContextBuffer[ROLE_OFFSET] == FiraConstant.INITIATOR;
    }

    public void setOrResetContext(boolean val) {
        mContextBuffer[OCCUPIED_OFFSET] = (byte) (val == true ? 1 : 0);
    }
}
