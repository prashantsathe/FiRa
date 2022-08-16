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
package com.android.javacard.ber;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class BerTlvParser {
    private BerArrayLinkList mTlvsLL;
    private short mGlobalOffset[];

    public BerTlvParser() {
        mTlvsLL = new BerArrayLinkList();
        mGlobalOffset = (short []) JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mGlobalOffset[0] = 0;
    }

    public BerArrayLinkList parse(byte[] buffer, short offset, short length) {

        short berTlvPtr = -1;

        mTlvsLL.resetLinkList();
        mGlobalOffset[0] = 0;

        if ((countNumberOfTags(buffer, offset, length) == 0) || length == 0) return null;

        short tOffset = offset;
        short startLLOffset = 2;

        // Keeping maximum tags count 100.
        for (short i = 0; i < 100 ; i++) {
            berTlvPtr = getTlvFrom(buffer, offset, tOffset, (short) (length - tOffset - offset),
                    false);

            if(berTlvPtr == -1) break;
            mTlvsLL.addToBottom(berTlvPtr, startLLOffset);

            if(mGlobalOffset[0] >= (short) (offset + length)) {
                break;
            }

            tOffset = mGlobalOffset[0];
        }

        return mTlvsLL;
    }

    public BerArrayLinkList getBerArrayLinkList() {
    	return mTlvsLL;
    }

    private short getTlvFrom(byte[] buffer, short offset, short tOffset, short len,
            boolean cObject) {

        if (((short)(tOffset + len) > buffer.length) || buffer[tOffset] == 0)  {
            return -1;
        }

        // Tag calculation
        short tagBytesCount = getTotalTagBytesCount(buffer, tOffset);
        short tagOffset = tOffset;

        // length calculation
        short lengthBytesCount = getTotalLengthBytesCount(buffer, (short) (tOffset + tagBytesCount));
        short berLength = getDataLength(buffer, (short) (tOffset + tagBytesCount));

        short valueOffset = (short) (tOffset + tagBytesCount + lengthBytesCount);
        short finalOffset = (short) (valueOffset + berLength);
        mGlobalOffset[0] = finalOffset;

        short tlvPtrOffset = mTlvsLL.allocateBerTlv(cObject);

        // value calculation
        // if Bit 5 is set it's a "constructed data object"
        if ((buffer[tOffset] & 0x20) == 0x20) {
            short newPtrSublistOffset = addSubListBerTlv(buffer, offset, valueOffset, berLength,
                    tlvPtrOffset);
            mTlvsLL.createBerTlv((short) (tagOffset - offset), tagBytesCount,
                    (short) (valueOffset - offset), berLength, tlvPtrOffset, newPtrSublistOffset);
            mGlobalOffset[0] = finalOffset;
        } else {
            mTlvsLL.createBerTlv((short) (tagOffset - offset), tagBytesCount,
                    (short) (valueOffset - offset), berLength, tlvPtrOffset, (short) -1);
        }

        return tlvPtrOffset;
    }

    private short addSubListBerTlv(byte[] buffer, short offset, short vOffset, short valueLength,
            short tlvParentOffset) {

        short startPosition = vOffset;
        short len = valueLength;
        short retOffset = -1; // represent First offset of list

        while (startPosition < (short) (vOffset + valueLength)) {
            short berTlvPtr = getTlvFrom(buffer, offset, startPosition, len, retOffset == -1);

            if (retOffset == -1)
                retOffset = berTlvPtr;

            mTlvsLL.addToBottom(berTlvPtr, retOffset);
            startPosition = mGlobalOffset[0];
            len = (short) ((vOffset + valueLength) - startPosition);
        }

        return retOffset;
    }

    public static short getTotalTagBytesCount(byte[] buffer, short offset) {

        if ((buffer[offset] & 0x1F) == 0x1F) { // see subsequent bytes
            short len = 2;
            for(short i = (short) (offset + 1); i < (short) (offset + 10); i++) {
                if( (buffer[i] & 0x80) != 0x80) {
                    break;
                }
                len++;
            }
            return len;
        } else {
            return (short)1;
        }
    }

    public static short getTotalLengthBytesCount(byte[] buffer, short offset) {

        short len = (short) (buffer[offset] & 0xff);

        if ((len & 0x80) == 0x80) {
            return (short) (1 + (len & 0x7f));
        } else {
            return 1;
        }
    }

    public static short getDataLength(byte[] buffer, short offset) {

        short length = (short) (buffer[offset] & 0xff);

        if ((length & 0x80) == 0x80) {
            short numberOfBytes = (short) (length & 0x7f);

            if (numberOfBytes > 3) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            length = 0;
            for (short i = (short) (offset + 1); i < (short) (offset + 1 + numberOfBytes); i++) {
                length = (short) (length * 0x100 + (buffer[i] & 0xff));
            }

        }
        return length;
    }

    public static short countNumberOfTags(byte[] buffer, short offset, short length) {

        short count = 0, tOffset = offset, tagByteCnt = 0, lengthByteCnt = 0, valueCount = 0;

        while (tOffset < (short)(length + offset)) {
            if (buffer[tOffset] == 0) break;

            tagByteCnt =  getTotalTagBytesCount(buffer, tOffset);
            lengthByteCnt = getTotalLengthBytesCount(buffer, (short) (tOffset + tagByteCnt));
            valueCount = getDataLength(buffer, (short) (tOffset + tagByteCnt));

            tOffset += (tagByteCnt +lengthByteCnt + valueCount);
            count++;
        }
        return count;
    }
}
