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
 Above structure hold offset information from a buffer representing BER encoded data

 Array based LinkList Example (All information are stored in Array)
 First two short data Elements are used as a link list reference pointers to root and tail of the list
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
| Root Ptr | tail Ptr | tagOffSet  | tagByteCount | lengthOffset | lengthByteCount | nextSubLinkListOffset | NextOffset| {Next structure data} | {Next structure data} |
| (Offset) | (Offset) |            |              |              |                 |          |            |  -------->|---------------------->|---------------------->NULL
----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------
                                                                                              |
                            |-----------------------------------------------------------------|
                            |
                            V
 --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 | Root Ptr | tail Ptr | tagOffSet  | tagByteCount | lengthOffset | lengthByteCount | nextSubLinkListOffset | NextOffset |  {Next structure data} | {Next structure data} |
 | (Offset) | (Offset) |            |              |              |                 |                       |            |                        |                       |
 --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

 ******************************************************************************/
public class BerArrayLinkList {
    private short size;
    private short maxSize;
    private short offset;
    private short[] llBuffer;
    private final short DEFAULT_SIZE = 20;
    private final short START_OFFSET = 2;
    private final short ROOT_OFFSET = -2;
    private final short TAIL_OFFSET = -1;

    public final static short BLOCK_SIZE = (1/* Tag offset */       + 1 /* tag byte count*/) +
                                            (1/* length offset */    + 1 /* length */) +
                                            (1/* Next Sub-linklist*/ + 1 /* Next offset */);

    public void AllocateLinkList() {
        AllocateLinkList(DEFAULT_SIZE);
    }

    public void AllocateLinkList(short size) {
        allocateBERLinkList(size);
    }

    private void allocateBERLinkList(short size) {
        this.maxSize = size;
        this.size = 0;
        this.offset = START_OFFSET;
        llBuffer = JCSystem.makeTransientShortArray((short) (size * BLOCK_SIZE), JCSystem.CLEAR_ON_DESELECT);
        llBuffer[0] = llBuffer[1] = -1; // Root&Tail to -1/null
    }

    public short allocateBerTlv(boolean newList) {
        short returnPtr = -1;
        if (this.size >= maxSize) return returnPtr;

        if (newList) {
            returnPtr = (short) (START_OFFSET + offset);
            offset += (BLOCK_SIZE + START_OFFSET);
            llBuffer[(short)(returnPtr + ROOT_OFFSET)] = llBuffer[((short)(returnPtr + TAIL_OFFSET))] = -1;
        } else {
            returnPtr = offset;
            offset += BLOCK_SIZE;
        }

        return returnPtr;
    }

    public void createBerTlv(short tagOffset, short tagByteLength,
                             short lengthOffset, short length,
                             short tlvPtrOffset, short subLinkListPtr) {
        llBuffer[tlvPtrOffset] = tagOffset;
        llBuffer[(short)(tlvPtrOffset + 1)] = tagByteLength;
        llBuffer[(short)(tlvPtrOffset + 2)] = lengthOffset;
        llBuffer[(short)(tlvPtrOffset + 3)] = length;
        llBuffer[(short)(tlvPtrOffset + 4)] = subLinkListPtr;
    }

    public void addToTop(short tlvPtrOffset) {

    }

    public void addToBottom(short berTlvPtr, short firstElementOffset) {
        /* TODO: Corner condition check */

        if (llBuffer[(short) (firstElementOffset + ROOT_OFFSET)] == -1) {
            llBuffer[(short)(firstElementOffset + ROOT_OFFSET)] = llBuffer[(short)(firstElementOffset + TAIL_OFFSET)] = berTlvPtr;
        } else {
            short tailOffset = llBuffer[(short)(firstElementOffset + TAIL_OFFSET)];

            llBuffer[(short)(tailOffset + 5)] = berTlvPtr;
            llBuffer[(short)(firstElementOffset + TAIL_OFFSET)] = berTlvPtr;
        }
        llBuffer[(short)(berTlvPtr + 5)] = -1; // NULL
        size++;
    }

//    public void printAllTags(byte[] buffer) {
//        printTLV(START_OFFSET, buffer);
//    }

//    /* TODO: Remove this function /  printing statements */
//    private void printTLV(short OffSet, byte[] buffer) {
//        short next = llBuffer[OffSet + ROOT_OFFSET];
//
//        while (next != -1) {
//
//            if (llBuffer[next + 4] != -1) {
//                System.out.println("Constructed data Object: "
//                        + "FirstTagByte=[" + buffer[llBuffer[next]] + "] "+ " TagByteCnt=" + llBuffer[next + 1]
//                        +" TotalLength="+ llBuffer[next + 3] + "\n{ ");
//                printTLV(llBuffer[next + 4], buffer);
//                System.out.println("}");
//            } else {
//                System.out.println("TAG=[" + buffer[llBuffer[next]] + "] "+ " TagByteCnt=" + llBuffer[next + 1]
//                        +" firstByteLength="+ buffer[llBuffer[next + 2]] +" TotalLength="+ llBuffer[next + 3]);
//            }
//            next = llBuffer[next + 5];
//        }
//    }

    public short getTLVInstance(short tlvOffset, short fromPtr) {
        short tmp = tlvOffset;
        short ptr = llBuffer[2 + ROOT_OFFSET];

        if (fromPtr == -1)
            ptr = fromPtr;

        while (0 != (tmp--)) {
            ptr = llBuffer[(short)(ptr + 5)];
        }

        //return llBuffer[ptr];
        return ptr;
    }

    public short getNextTag(short fromPtr) {
        return llBuffer[(short)(fromPtr + 5)];
    }

    public short getTagOffset(short tlvOffset) {
        return llBuffer[tlvOffset];
    }

    public short getLength(short tlvPtr) {
        return llBuffer[(short)(tlvPtr + 3)];
    }


}
