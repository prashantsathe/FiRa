package com.android.ber;

import javacard.framework.JCSystem;

/******************************************************************************
 * Array index based Link list structure

 Struct {
    short tagOffSet
    short tagByteCount
    short lengthOffset
    short lengthByteCount
    short nextSubLinkListOffset --> Set for constructed data object otherwise set to -1
    short NextOffset
 }
 Above structure hold offset information from a buffer representing a BER encoded data

 Array based LinkList Example (All information are stored in Array)
 First two short data Elements are used as a link list reference pointers for adding data Top&Bottom of the list
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| Root Ptr | tail Ptr | tagOffSet  | tagByteCount | lengthOffset | lengthByteCount | nextSubLinkListOffset | NextOffset| {Next structure data} | {Next structure data} |
| (Offset) | (Offset) |            |              |              |                 |          |            |  -------->|---------------------->|---------------------->NULL
----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------
                                                                                              |
       |--------------------------------------------------------------------------------------|
       |
       V
 --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 | Root Ptr | tail Ptr | tagOffSet  | tagByteCount | lengthOffset | lengthByteCount | nextSubLinkListOffset | NextOffset |  {Next structure data} | {Next structure data} |
 | (Offset) | (Offset) |            |              |              |                 |                       |            |                        |                       |
 --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


 ******************************************************************************/

public class BerArrayLinkList {
    private short size;
    private short offset;
    private short[] llBuffer;
    private final short DEFAULT_SIZE = 10;
    private final short BLOCK_SIZE = (1/* Tag offset */       + 1 /* tag byte count*/) +
                                     (1/* length offset */    + 1 /* length byte Count*/) +
                                     (1/* Next Sub-linklist*/ + 1 /* Next offset */);
    private final short ROOT_OFFSET = -2;
    private final short TAIL_OFFSET = -1;

    public void AllocateLinkList() {
        this.size = DEFAULT_SIZE;
        this.offset = 2;
        AllocateLinkList(DEFAULT_SIZE);
        llBuffer[0] = llBuffer[1] = -1; // Root&Tail to -1/null
    }

    public void AllocateLinkList(short size) {
        this.size = size;
        this.offset = 2;
        AllocateBERLinkList(size);
        llBuffer[0] = llBuffer[1] = -1; // Root&Tail to -1/null
    }

    public short AllocateBerTlv(boolean newList) {
        short returnPtr;

        if (newList) {
            returnPtr = (short) (2 + offset);
            offset += (BLOCK_SIZE + 2);
            llBuffer[returnPtr + ROOT_OFFSET] = llBuffer[returnPtr + TAIL_OFFSET] = -1;
        } else {
            returnPtr = offset;
            offset += BLOCK_SIZE;
        }

        return returnPtr;
    }

    public void CreateBerTlv(short tagOffset, short tagByteLength, short tlvPtrOffset) {
        llBuffer[tlvPtrOffset] = tagOffset;
        llBuffer[tlvPtrOffset + 1] = tagByteLength;
    }

    public void AddToTop(short tlvPtrOffset) {

    }

    public void AddToBottom(short berTlvPtr, short firstElementOffset) {
        /* TODO: Corner condition check */

        if (llBuffer[firstElementOffset + ROOT_OFFSET] == -1) {
            llBuffer[firstElementOffset + ROOT_OFFSET] = llBuffer[firstElementOffset + TAIL_OFFSET] = berTlvPtr;
        } else {
            short tailOffset = llBuffer[firstElementOffset + TAIL_OFFSET];

            llBuffer[tailOffset + 5] = berTlvPtr;
            llBuffer[firstElementOffset + TAIL_OFFSET] = berTlvPtr;
            llBuffer[berTlvPtr + 5] = -1; // NULL
        }

        size++;
    }

    private void AllocateBERLinkList(short size) {
        llBuffer = JCSystem.makeTransientShortArray((short) (size * BLOCK_SIZE), JCSystem.CLEAR_ON_DESELECT);
    }
}
