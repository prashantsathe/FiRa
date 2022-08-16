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

import com.android.javacard.ber.BerTlvParser;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class ClientContext {
    // FiRa keys/certificates functions list
    public static boolean getADFPrivacy(byte[] oidBuff, short oidBuffOffset, byte oidBuffLength) {
        return false;
    }

    public static short getADFdata(byte[] oidBuff, short oidBuffOffset, byte oidBuffLength,
            byte[] buffer, short bufferOffset) {
        return (short) (Util.arrayFillNonAtomic(buffer, bufferOffset, (short) 512,
                (byte) 0x02) - bufferOffset);
    }

    public static short getLabel(byte[] oidBuff, short oidBuffOffset, byte oidBuffLength,
            byte[] buffer, short bufferOffset) {
        buffer[bufferOffset++] = 0x01;
        buffer[bufferOffset++] = 0x02;
        buffer[bufferOffset++] = 0x03;
        buffer[bufferOffset++] = 0x04;
        return (short) 4;
    }

    // Table 74/75/76 of CSML CR v0.9_v123-TWG-May28-NXP-CSMLTT-NXP_ab.pdf
    public static short getFiRaCert2(byte[] buffer, short bufferOffset, FiraClientContext ctx) {
        return ctx.getSDCertificate(buffer, bufferOffset);
    }

    public static short getKeyOffet(byte scIdentifier, byte keyType, byte[] keySetBuff,
            short keySetBuffOffset, short keySetBuffLen) {
        short offset = -1;
        short index = keySetBuffOffset;
        short totalLen = (short) (keySetBuffOffset + keySetBuffLen);
        boolean identifierMatch = false;
        short totalLengthByteCount = 0;

        // first byte must be of Constructed Tag
        if ((keySetBuff[index] & 0x20) != 0x20) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Header is always one byte (Table: 78/79/80)
        index += (BerTlvParser.getTotalLengthBytesCount(keySetBuff, (short) (index + 1)) + 1);

        while (index < totalLen) {

            // All tags of FiRa Secure Channel Credentials are 1 bytes
            totalLengthByteCount = BerTlvParser.getTotalLengthBytesCount(keySetBuff,
                    (short) (index + 1));

            if (keySetBuff[index] == (byte) 0x80
                    && scIdentifier == keySetBuff[(short) (index + totalLengthByteCount + 1)]) {
                identifierMatch = true;
            } else if (keyType == keySetBuff[index]) {
                offset = (short) (index + 2);
            }

            index += (1 + totalLengthByteCount +
                    BerTlvParser.getDataLength(keySetBuff, (short) (index + 1)));
        }

        if (offset == -1 || identifierMatch == false) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        return offset;
    }

    public static short getTagValueOffset(byte tag, byte[] keySetBuff, short keySetBuffOffset,
            short keySetBuffLen) {
        short offset = -1;
        short index = keySetBuffOffset;
        short totalLen = (short) (keySetBuffOffset + keySetBuffLen);
        short totalLengthByteCount = 0;

        // first byte must be of Constructed Tag
        if ((keySetBuff[index] & 0x20) != 0x20) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Header is always one byte (Table: 78/79/80)
        index += (BerTlvParser.getTotalLengthBytesCount(keySetBuff, (short) (index + 1)) + 1);

        while (index < totalLen) {
            // All tags of FiRa Secure Channel Credentials are 1 bytes
            totalLengthByteCount = BerTlvParser.getTotalLengthBytesCount(keySetBuff,
                    (short) (index + 1));

            if (keySetBuff[index] == tag) {
                offset = (short) (index + totalLengthByteCount + 1);
                break;
            }

            index += (1 + totalLengthByteCount + BerTlvParser.getDataLength(keySetBuff,
                    (short) (index + 1)));
        }

        return offset;
    }
    // FiRa keys/certificates functions list .. end

    // SCP11c keys/certificates function list
    public static short getPkCaKlocEcdsa(byte kvn, byte[] keyBuff, short keyBuffOffset,
            FiraClientContext ctx) {
        return ctx.getCAPublicKey(kvn,keyBuff,keyBuffOffset);
    }

    public static short getSkSdEcka(byte kvn, byte[] keyBuff, short keyBuffOffset, FiraClientContext ctx) {
        short ret = ctx.getSDSecretKey(keyBuff,keyBuffOffset);
        if (ret == FiraClientContext.INVALID_VALUE) {
            return 0;
        }
        return ret;
    }

    public static short getPkSdEcka(byte kvn, byte[] keyBuff, short keyBuffOffset) {
        short index = keyBuffOffset;

        // TODO: remove it; used it for testing purpose
        // 04 73103EC3 0B3CCF57 DAAE08E9 3534AEF1 44A35940 CF6BBBA1 2A0CF7CB D5D65A64
        // D82C8C99 E9D3C45F 9245BA9B 27982C9A EA8EC1DB 94B19C44 795942C0 EB22AA32
        keyBuff[index++] = 0x04; keyBuff[index++] = 0x73; keyBuff[index++] = 0x10; keyBuff[index++] = 0x3e;
        keyBuff[index++] = (byte)0xc3; keyBuff[index++] = 0x0b; keyBuff[index++] = 0x3c; keyBuff[index++] = (byte)0xcf;
        keyBuff[index++] = 0x57; keyBuff[index++] = (byte)0xda; keyBuff[index++] = (byte)0xae; keyBuff[index++] = 0x08;
        keyBuff[index++] = (byte)0xe9; keyBuff[index++] = 0x35; keyBuff[index++] = 0x34; keyBuff[index++] = (byte)0xae;
        keyBuff[index++] = (byte)0xf1; keyBuff[index++] = 0x44; keyBuff[index++] = (byte)0xa3; keyBuff[index++] = 0x59;
        keyBuff[index++] = 0x40; keyBuff[index++] = (byte)0xcf; keyBuff[index++] = 0x6b; keyBuff[index++] = (byte)0xbb;
        keyBuff[index++] = (byte)0xa1; keyBuff[index++] = 0x2a; keyBuff[index++] = 0x0c; keyBuff[index++] = (byte)0xf7;
        keyBuff[index++] = (byte)0xcb; keyBuff[index++] = (byte)0xd5; keyBuff[index++] = (byte)0xd6; keyBuff[index++] = 0x5a;
        keyBuff[index++] = 0x64; keyBuff[index++] = (byte)0xd8; keyBuff[index++] = 0x2c; keyBuff[35] = (byte)0x8c;
        keyBuff[index++] = (byte)0x99; keyBuff[index++] = (byte)0xe9; keyBuff[index++] = (byte)0xd3; keyBuff[index++] = (byte)0xc4;
        keyBuff[index++] = 0x5f; keyBuff[index++] = (byte)0x92; keyBuff[index++] = 0x45; keyBuff[index++] = (byte)0xba;
        keyBuff[index++] = (byte)0x9b; keyBuff[index++] = 0x27; keyBuff[index++] = (byte)0x98; keyBuff[index++] = 0x2c;
        keyBuff[index++] = (byte)0x9a; keyBuff[index++] = (byte)0xea; keyBuff[index++] = (byte)0x8e; keyBuff[index++] = (byte)0xc1;
        keyBuff[index++] = (byte)0xdb; keyBuff[index++] = (byte)0x94; keyBuff[index++] = (byte)0xb1; keyBuff[index++] = (byte)0x9c;
        keyBuff[index++] = 0x44; keyBuff[index++] = 0x79; keyBuff[index++] = 0x59; keyBuff[index++] = 0x42;
        keyBuff[index++] = (byte)0xc0; keyBuff[index++] = (byte)0xeb; keyBuff[index++] = 0x22; keyBuff[index++] = (byte)0xaa;
        keyBuff[index++] = 0x32;

        return (short) (index - keyBuffOffset);
    }

    public static boolean verifyCSN(byte[] csnBuff, short csnBuffOffset, short csnBuffLength) {
        return true;
    }
    // SCP11c keys/certificates function list .. end
}
