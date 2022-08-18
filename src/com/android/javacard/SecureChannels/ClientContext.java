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

    public static short getSkSdEcka(byte kvn, byte[] keyBuff, short keyBuffOffset,
            FiraClientContext ctx) {
        return ctx.getSDSecretKey(keyBuff, keyBuffOffset);
    }

    public static short getPkSdEcka(byte kvn, byte[] keyBuff, short keyBuffOffset,
            FiraClientContext ctx) {
        short size = ctx.getSDCertificate(keyBuff, keyBuffOffset);

        if (size != (short) 0) {
            // extract public key
            // NOTE: we always validate the certificate before provisioning
            //       So public key and certificate header must be present
            //       we may have multiple SD certificates, we have implemented PK extraction from
            //       first certificate. (SD Cert selection based on ??)
            //       'keyBuff' contains TAG_CERTIFICATE header
            short index = 2; // for 'TAG_CERTIFICATE'
            short cerLenByteCnt = BerTlvParser.getTotalLengthBytesCount(keyBuff,
                    (short) (keyBuffOffset + index));
            short cerLen = BerTlvParser.getDataLength(keyBuff, (short) (keyBuffOffset + index));
            index += cerLenByteCnt;

            // travel till 'TAG_PUBLIC_KEY'
            short tagByteCnt = 0, tag = 0, lenByteCnt = 0, dataLen = 0;
            while (index < cerLen) {
                tagByteCnt = BerTlvParser.getTotalTagBytesCount(keyBuff,
                        (short) (keyBuffOffset + index));

                tag = tagByteCnt == 1 ?
                        (short) (keyBuff[(short) (keyBuffOffset + index)] & (short) 0xFF) :
                            Util.getShort(keyBuff, (short) (keyBuffOffset + index));

                index += tagByteCnt;
                lenByteCnt = BerTlvParser.getTotalLengthBytesCount(keyBuff,
                        (short) (keyBuffOffset + index));
                dataLen = BerTlvParser.getDataLength(keyBuff, (short) (keyBuffOffset + index));
                index += lenByteCnt;

                if (tag == ScpConstant.TAG_PUBLIC_KEY) {
                    break;
                }
                // new index offset 
                index += dataLen;
            }

            // now index should be pointing to TAG_PUBLIC_KEY_Q
            // refer Table 51 – Certificate for reader and device
            Util.arrayCopyNonAtomic(keyBuff, (short) (keyBuffOffset + index + 2), keyBuff,
                    keyBuffOffset, keyBuff[(short) (keyBuffOffset + index + 1)]);
            size = keyBuff[(short) (keyBuffOffset + index + 1)];
        }
        return size;
    }

    public static boolean verifyCSN(byte[] csnBuff, short csnBuffOffset, short csnBuffLength) {
        return true;
    }
    // SCP11c keys/certificates function list .. end
}
