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

import javacard.framework.JCSystem;

/******************************************************************************
 * Array index based Link list structure

 Struct {
    short tagOffSet
    short tagByteCount
    short vOffset
    short vlength
    short nextSubLinkListOffset --> Set for constructed data object otherwise set to -1
    short NextOffset
 }
 Above structure hold offset information from a buffer representing BER encoded data

 Array based LinkList Example (All information are stored in Array)
 First two short data Elements are used as a link list reference pointers to root and tail of the list
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| Root Ptr | tail Ptr | tagOffSet  | tagByteCount | vOffset | vlength | nextSubLinkListOffset | NextOffset| {Next structure data} | {Next structure data} |
| (Offset) | (Offset) |            |              |         |         |          |            |  -------->|---------------------->|---------------------->NULL
---------------------------------------------------------------------------------|---------------------------------------------------------------------------------
                                                                                 |
                            |----------------------------------------------------|
                            |
                            V
 --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 | Root Ptr | tail Ptr | tagOffSet  | tagByteCount | vOffset | vlength  | nextSubLinkListOffset | NextOffset |  {Next structure data} | {Next structure data} |
 | (Offset) | (Offset) |            |              |         |          |                       |            |                        |                       |
 --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

 ******************************************************************************/
public class BerArrayLinkList {

    private short[] mSizeInfo;
    private short[] mCurrentSize;
    private short[] mLLBuffer;
    private final short DEFAULT_SIZE = 20;
    private final short START_OFFSET = 2;
    private final short ROOT_OFFSET = -2;
    private final short TAIL_OFFSET = -1;

    public final static short BLOCK_SIZE =  (1/* Tag offset */       + 1 /* tag byte count*/) +
                                            (1/* value offset */     + 1 /* vLength */) +
                                            (1/* Next Sub-linklist*/ + 1 /* Next offset */);

    public BerArrayLinkList() {
    	AllocateLinkList(DEFAULT_SIZE);
    }

    public void AllocateLinkList(short size) {
        allocateBERLinkList(size);
    }

    private void allocateBERLinkList(short size) {
        // 0 - size
        // current size of BER array
        mCurrentSize = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mCurrentSize[0] = 0;

        // 0 - max Size
        // 1 - Start offset of the array
        mSizeInfo = new short[2];
        mSizeInfo[0] = size;
        mSizeInfo[1] = START_OFFSET;

        mLLBuffer = JCSystem.makeTransientShortArray((short) (size * BLOCK_SIZE), 
                JCSystem.CLEAR_ON_RESET);
        mLLBuffer[0] = mLLBuffer[1] = -1; // Root&Tail to -1/null
    }

    public short allocateBerTlv(boolean newList) {
        short returnPtr = -1;
        if (this.mCurrentSize[0] >= mSizeInfo[0]) return returnPtr;

        if (newList) {
            returnPtr = (short) (START_OFFSET + mSizeInfo[1]);
            mSizeInfo[1] += (BLOCK_SIZE + START_OFFSET);
            mLLBuffer[(short)(returnPtr + ROOT_OFFSET)] = mLLBuffer[((short)(returnPtr + TAIL_OFFSET))] = -1;
        } else {
            returnPtr = mSizeInfo[1];
            mSizeInfo[1] += BLOCK_SIZE;
        }

        return returnPtr;
    }

    public void createBerTlv(short tagOffset, short tagByteLength,
                             short vOffset, short vlength,
                             short tlvPtrOffset, short subLinkListPtr) {
        mLLBuffer[tlvPtrOffset] = tagOffset;
        mLLBuffer[(short)(tlvPtrOffset + 1)] = tagByteLength;
        mLLBuffer[(short)(tlvPtrOffset + 2)] = vOffset;
        mLLBuffer[(short)(tlvPtrOffset + 3)] = vlength;
        mLLBuffer[(short)(tlvPtrOffset + 4)] = subLinkListPtr;
    }

    public void resetLinkList() {
        mCurrentSize[0] = 0;
        mSizeInfo[1] = START_OFFSET;
        mLLBuffer[0] = -1; mLLBuffer[1] = -1;
    }

    public void addToBottom(short berTlvPtr, short firstElementOffset) {
        /* TODO: Corner condition check */

        if (mLLBuffer[(short) (firstElementOffset + ROOT_OFFSET)] == -1) {
            mLLBuffer[(short)(firstElementOffset + ROOT_OFFSET)] = 
                    mLLBuffer[(short)(firstElementOffset + TAIL_OFFSET)] = berTlvPtr;
        } else {
            short tailOffset = mLLBuffer[(short)(firstElementOffset + TAIL_OFFSET)];

            mLLBuffer[(short)(tailOffset + 5)] = berTlvPtr;
            mLLBuffer[(short)(firstElementOffset + TAIL_OFFSET)] = berTlvPtr;
        }

        mLLBuffer[(short)(berTlvPtr + 5)] = -1; // NULL
        mCurrentSize[0]++;
    }

    /*
    public short getTLVInstance(short tlvOffset, short fromPtr) {
        short tmp = tlvOffset;
        short ptr = mLLBuffer[2 + ROOT_OFFSET];

        if (fromPtr == -1)
            ptr = fromPtr;

        while (0 != (tmp--)) {
            ptr = mLLBuffer[(short)(ptr + 5)];
        }

        return ptr;
    }
    */

    public short getFirstTLVInstance() {
        return mLLBuffer[2 + ROOT_OFFSET];
    }

    public short getNextTag(short fromPtr) {
        return mLLBuffer[(short)(fromPtr + 5)];
    }

    public short getTagOffset(short tlvOffset) {
        return mLLBuffer[tlvOffset];
    }

    public short getTagByteCount(short tlvOffset) {
        return mLLBuffer[(short) (tlvOffset + 1)];
    }

    public short getValueOffset(short tlvOffset) {
        return mLLBuffer[(short) (tlvOffset + 2)];
    }

    public short getLength(short tlvPtr) {
        return mLLBuffer[(short)(tlvPtr + 3)];
    }

    public short getNextSubLinkOffset(short tlvOffset) {
        return mLLBuffer[(short) (tlvOffset + 4)];
    }

    public short getTotalTlvLength(short tlvPtr) {

        short lengthByteCount;

        if (mLLBuffer[(short)(tlvPtr + 3)] < 128) {
            lengthByteCount = 1;
        } else if (mLLBuffer[(short)(tlvPtr + 3)] < 256) {
            lengthByteCount = 2;
        } else {
            lengthByteCount = 3;
        }

        return (short) (mLLBuffer[(short)(tlvPtr + 1)] +  mLLBuffer[(short)(tlvPtr + 3)] +
                lengthByteCount);
    }

}
