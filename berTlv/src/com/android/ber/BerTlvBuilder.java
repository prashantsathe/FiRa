package com.android.ber;

import javacard.framework.JCSystem;

public class BerTlvBuilder {
    private BerList tlvs;
    private short bPosition;

    public BerTlvBuilder() {
        bPosition = 0;
        /* TODO: null check */
        tlvs = new BerList();
    }

    public BerTlvBuilder(short listLength) {
        /* TODO: null check */
        tlvs = new BerList(listLength);
    }

    public void AddTlv(byte[] tag, short tagBytesCount, byte[] buffer, short length) {
        BerTlv tlv = GetTlvfrom(tag, tagBytesCount, buffer, (short) 0, length);
        if (tlv != null) {
            tlvs.add(tlv);
        }
    }

    public void AddTemplate(byte[] tag, short tagBytesCount) {
        /* TODO:- do it using transient memory & error check*/
        BerTlv tlv = new BerTlv();

        if (tlv != null) {
            // Tag calculation
            tlv.berTagPtr       = createTag(tag, (short) 0, tagBytesCount);

            // length calculation
            tlv.berLengthPtr    = createLength(null, (short) 0, bPosition);
            tlv.berLength       = getDataLength(tlv.berLengthPtr , (short) 0);
            tlvs.add(tlv);
        }
    }

    private BerTlv GetTlvfrom(byte[] tag, short tagBytesCount, byte[] buffer, short offset, short len) {

        /* TODO:- do it using transient memory & error check*/
        BerTlv tlv = new BerTlv();

        if (offset + len > buffer.length) {
            // TODO: throw exception
        }

        // Tag calculation
        tlv.berTagPtr       = createTag(tag, (short) 0, tagBytesCount);

        // length calculation
        tlv.berLengthPtr    = createLength(buffer, (short) 0, len);
        tlv.berLength       = getDataLength(buffer, (short) 0);

        // value calculation
        tlv.berValuePtr     = createValue(buffer, (short) 0, tlv.berLength);

        bPosition += (tagBytesCount + tlv.berLength + len);

        return tlv;
    }

    /* TODO:- Need to change the length for 'int' type
     *        And w.r.t same parser code changes
     */
    private short CalculateBytesCountForLength(short aLength) {
        short ret = 0;
        if(aLength < 0x80) {
            ret = 1;
        } else if (aLength <0x100) {
            ret = 2;
        } else if( aLength < 0x10000) {
            ret = 3;
        } else if( aLength < 0x1000000 ) {
            ret = 4;
        } else {
            // throw new IllegalStateException("length ["+aLength+"] out of range (0x1000000)");
        }
        return ret;
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

    private byte[] createTag(byte[] buffer, short offset, short len) {
        byte[] tag = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);

        /* Copy tags */
        System.arraycopy(buffer, offset, tag, 0, len);
        return tag;
    }

    private byte[] createLength(byte[] buffer, short offset, short len) {
        short lengthByteCount = CalculateBytesCountForLength(len); //getTotalLengthBytesCount(buffer, offset);
        byte[] lengthPtr = JCSystem.makeTransientByteArray(lengthByteCount, JCSystem.CLEAR_ON_DESELECT);

        /* Copy length */
        if (buffer != null) {
            System.arraycopy(buffer, offset, lengthPtr, 0, lengthByteCount);
        } else {
            if(len < 0x80) {
                lengthPtr[offset] = (byte) len;

            } else if (len <0x100) {
                lengthPtr[offset] = (byte) 0x81;
                lengthPtr[offset+1] = (byte) len;

            } else if( len < 0x10000) {

                lengthPtr[offset]   = (byte) 0x82;
                lengthPtr[offset + 1] = (byte) (len / 0x100);
                lengthPtr[offset + 2] = (byte) (len % 0x100);

            } else if( len < 0x1000000 ) {
                lengthPtr[offset]   = (byte) 0x83;
                lengthPtr[offset + 1] = (byte) (len / 0x10000);
                lengthPtr[offset + 2] = (byte) (len / 0x100);
                lengthPtr[offset + 3] = (byte) (len % 0x100);
            } else {
                throw new IllegalStateException("length ["+len+"] out of range (0x1000000)");
            }
        }
        return lengthPtr;
    }

    private byte[] createValue(byte[] buffer, short offset, short len) {
        byte[] value = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);

        /* Copy Value */
        System.arraycopy(buffer, offset, value, 0, len);
        return value;
    }
}
