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

package com.android.javacard.SusApplet;

final class Constants {
    // INS
    public static final byte INS_SELECT = (byte) 0xA4;
    public static final byte INS_INT_AUTH = 0x50;
    public static final byte INS_PSO = 0x2A;
    public static final byte INS_EXT_MUT_AUTH = (byte) 0x82;
    public static final byte INS_GET_RDS_DATA = 0x40;
    public static final byte INS_ERASE_RDS = 0x41;

    // RDS constants
    public static final byte RANGING_SESSION_KEY = (byte) 0xC0;
    public static final byte UWB_SESSION_ID = (byte) 0xCF;
    public static final byte KEY_EXCHANGE_KEY_ID = (byte) 0xC6;
    public static final byte SEC_PRIVACY_KEY = (byte) 0xD1;

    // Select tag info
    public static final byte[] S_RESPONSE_TEMPLATE = { 0x6F };
    public static final byte[] S_SUS_APPLET_AID = { (byte) 0x84 };
    public static final byte[] S_A5 = { (byte) 0xA5 };
    public static final byte[] S_BFOC = { (byte) 0xBF, 0x0C };
    public static final byte[] S_SUS_APP_VERSION = { (byte) 0x9F, 0x7E };
    public static final byte[] S_SUS_APP_VERSION_INFO = { (byte) 0x01, 0x00 };
    public static final byte[] S_APPLET_OPTIONS = { 0x4C };
    public static final byte[] S_APPLET_OPTIONS_INFO = { 0x00, 0x00, 0x00 };

    // Custom SUS external API exception
    public static final short EXP_UNKNOWN_SESSION_ID = 25088; // ‘0x6200’ Warning: UWB Session ID
                                                              // unknown

    // GP security level
    // 0xB3 = crmacencrenc : C-MAC, R-MAC ,R-ENC and C-ENC, including AUTHENTICATED
    public static final byte SUS_GP_SECURITY_LEVEL = (byte) 0xB3;

    // SUS constants (Configurable parameters)
    public static final short TEMP_BUF_SIZE = 1024; // 1k
    public static final short MAX_RDS_COUNT = 4;
    public static final short RDS_MAX_DATA_SIZE = 256; // Keeping Key Exchange Key Identifier in 32
    public static final short AID_MAX_SIZE = 32;
    public static final short KEY_EXCHANGE_KEY_ID_MAX_DATA_SIZE = 32;
    public static final boolean STORE_RDS_PERSISTENT_FLAG = false;
    // package version is an addition of major version(2 bytes) + minor version(2 bytes)
    // example 100 = major version 100/100 = 1 and minor version 100%100 = 00
    //         101 = major version 100/100 = 1 and minor version 101%100 = 01 .. etc
    public static final short CURRENT_PACKAGE_VERSION = 100;
    // STORAGE_RDS_SIZE = ( mOccupied(1) + mUWBsessionIdOffset(2) +
    // mKeyExchangeKeyIdOffset(2)+ mKeyExchangeAppAid + mKeyExchangeAppAidSize(2) +
    // mRDSdata + rds_length(2))
    public static final short STORAGE_RDS_SIZE = (short) 9 + AID_MAX_SIZE + RDS_MAX_DATA_SIZE;

    // RDS data offsets
    public static final short O_OCCUPIED = 0;
    public static final short O_UWB_SESSION_ID = O_OCCUPIED + 1;
    public static final short O_KEY_EXCHANGE_ID = O_UWB_SESSION_ID + 2;
    public static final short O_KEY_EXCHANGE_APP_ID = O_KEY_EXCHANGE_ID + 2;
    public static final short O_KEY_EXCHANGE_APP_ID_SIZE = O_KEY_EXCHANGE_APP_ID + AID_MAX_SIZE;
    public static final short O_RDS = O_KEY_EXCHANGE_APP_ID_SIZE + 2;
    public static final short O_RDS_LENGTH = O_RDS + RDS_MAX_DATA_SIZE;
}
