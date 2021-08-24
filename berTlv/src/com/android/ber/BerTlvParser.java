package com.android.ber;

import javacard.framework.JCSystem;

import java.util.ArrayList;

public class BerTlvParser {

    public BerTlvParser() {

    }

    public BerList parser(byte[] buffer, short offset, short length)
    {
        short tagsCount;
        if (((tagsCount = CountNumberOfTags(buffer, offset, length)) == 0) || length == 0) return null;

        /* TODO: null check */
        BerList tlvs = new BerList(tagsCount);

        short tOffset = offset;
        /* TODO:- while(offset < length - 1) or max 100, release library has max 100 */
        for (short i = 0; i < 100 ; i++) {
            BerTlv tlv = GetTlvfrom(buffer, tOffset, (short) (length -  tOffset));
            tlvs.add(tlv);

            if(tlv.offset >= offset + length) {
                break;
            }

            tOffset = tlv.offset;
        }

        return tlvs;
    }

    private short CountNumberOfTags(byte[] buffer, short offset, short length)
    {
        short count = 0, tOffset = offset, tagByteCnt = 0, lengthByteCnt = 0, valueCount = 0;

        while (tOffset < (length + offset)) {
            tagByteCnt =  getTotalTagBytesCount(buffer, tOffset);
            lengthByteCnt = getTotalLengthBytesCount(buffer, (short) (tOffset + tagByteCnt));
            valueCount = getDataLength(buffer, (short) (tOffset + tagByteCnt));

            tOffset +=(tagByteCnt +lengthByteCnt + valueCount);
            count++;
        }
        return count;
    }

    private byte[] createTag(byte[] buffer, short offset, short len) {
        byte[] tag = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);

        /* Copy tags */
        System.arraycopy(buffer, offset, tag, 0, len);
        return tag;
    }

    private byte[] createLength(byte[] buffer, short offset) {
        short lengthByteCount = getTotalLengthBytesCount(buffer, offset);
        byte[] lengthPtr = JCSystem.makeTransientByteArray(lengthByteCount, JCSystem.CLEAR_ON_DESELECT);

        /* Copy length */
        System.arraycopy(buffer, offset, lengthPtr, 0, lengthByteCount);
        return lengthPtr;
    }

    private byte[] createValue(byte[] buffer, short offset, short len) {
        byte[] value = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);

        /* Copy Value */
        System.arraycopy(buffer, offset, value, 0, len);
        return value;
    }

    private short getTotalLengthBytesCount(byte[] buffer, short offset) {
        short len = (short) (buffer[offset] & 0xff);

        if ((len & 0x80) == 0x80) {
            return (short) (1 + (len & 0x7f));
        } else {
            return 1;
        }
    }

    private short getDataLength(byte[] buffer, short offset) {

        short length = (short) (buffer[offset] & 0xff);

        if ((length & 0x80) == 0x80) {
            short numberOfBytes = (short) (length & 0x7f);

            if (numberOfBytes > 3) {
                // TODO: throw exception
            }

            length = 0;
            for (short i = (short) (offset + 1); i < (offset + 1 + numberOfBytes); i++) {
                length = (short) (length * 0x100 + (buffer[i] & 0xff));
            }

        }
        return length;
    }

    private short getTotalTagBytesCount(byte[] buffer, short offset) {
        if ((buffer[offset] & 0x1F) == 0x1F) { // see subsequent bytes
            short len = 2;
            for(short i = (short) (offset + 1); i < offset + 10; i++) {
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

    private BerTlv GetTlvfrom(byte[] buffer, short offset, short len) {

        /* TODO:- do it using transient memory & error check*/
        BerTlv tlv = new BerTlv();

        if (offset + len > buffer.length) {
            // TODO: throw exception
        }

        // Tag calculation
        short tagBytesCount   = getTotalTagBytesCount(buffer, offset);
        tlv.berTagPtr         = createTag(buffer, offset, tagBytesCount);

        // length calculation
        short lengthBytesCount  = getTotalLengthBytesCount(buffer, (short) (offset + tagBytesCount));
        tlv.berLengthPtr      = createLength(buffer, (short) (offset + tagBytesCount));
        tlv.berLength         = getDataLength(buffer, (short) (offset + tagBytesCount));

        // value calculation
        // TODO: if Bit 5 is set; "constructed data object"
        if ((buffer[offset] & 0x20) == 0x20 ) {
            /* TODO:- do it using transient memory & error check*/
            tlv.berLinkList = new BerLinkList();
            tlv.berValuePtr = null;

            short valueOffset = (short) (offset + tagBytesCount + lengthBytesCount);
            AddSublistBerTlv(buffer, valueOffset, lengthBytesCount, tlv.berLength, tlv.berLinkList);
        } else {
            // TODO: remove 2 time calls to "getTotalLengthBytesCount"
            short valueOffset = (short) (offset + tagBytesCount + lengthBytesCount);
            tlv.offset = (short) (valueOffset + tlv.berLength);
            tlv.berValuePtr  = createValue(buffer, valueOffset, tlv.berLength);
            tlv.berLinkList = null;
        }

        return tlv;
    }

    private void AddSublistBerTlv(byte[] buffer, short aOffset, short aDataBytesCount,
                                  short valueLength, BerLinkList linkList) {
        short startPosition = aOffset;
        short len = valueLength;
        while (startPosition < aOffset + valueLength ) {
            //ParseResult result = parseWithResult(aLevel+1, buffer, startPosition, len);
            BerTlv tlv = GetTlvfrom(buffer,startPosition, len);
            linkList.AddToBottom(tlv);

            startPosition = tlv.offset;
            len           = (short) ((aOffset + valueLength) - startPosition);
        }
    }
}
