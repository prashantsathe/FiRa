package com.android.javacard.FiraApplet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * This class has methods to handle BER TLV related functions.
 */
public class FiraUtil {

  /**
   * BER TLV ignores//skips 0xFFs and 0s between two TLVs.
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @return index of the next non 0xFF and 0 byte.
   */
  public static short skipZerosAndFFs(byte[] buf, short index, short len){
    short end = (short)(index + len);
    // Ignore 00 and FF between two tags
    while(index < end){
      if(buf[index] != 0 && buf[index] != 0xFF){
        break;
      }
      index++;
    }
    return index;
  }

  /**
   * Read Tag id from the BER TLV object. In FiraApplet the tag id will only be one or two bytes long.
   * if the tag id is more than 2 bytes then ISO7816.SW_WRONG_DATA exception is thrown.
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @param retValues - The retValues[0] will return tag.
   * @return index pointing at the length field of the TLV object.
   */
  public static short readBERTag(byte[] buf, short index, short len, short[] retValues){
    if(len == 0) return FiraSpecs.INVALID_VALUE;
    if ((buf[index] & 0x1F) != 0x1F) { // 1 byte tag
      retValues[0] = (short)(buf[index] & (short)0x00FF);
    } else if ((buf[(short) (index + 1)] & 0x80) == 0) { //2 bytes
      retValues[0]= javacard.framework.Util.getShort(buf, index);
      index++;
    } else { // more than 2 bytes
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    index++;
    return index;
  }

  /**
   * Read Tag length from the BER TLV object. In FiraApplet the tag length will at maximum will be
   * 2 bytes long i.e. 32K. if the tag length is more than 2 bytes then ISO7816.SW_WRONG_LENGTH
   * exception is thrown.
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @param retValues - The retValues[0] will return tag length.
   * @return index pointing at start of the value field of the TLV object.
   */
  public static short readBERLength(byte[] buf, short index, short len, short[] retValues){
    retValues[0] = FiraSpecs.INVALID_VALUE;
    if(len == 0) return FiraSpecs.INVALID_VALUE;
    // If length is negative then there is n bytes of length ahead.
    // If length is positive then length is between 0 - 127.
    if (buf[index] < 0) {
      byte numBytes = (byte) (buf[index] & 0x7F);
      if (numBytes == 2) {
        index++;
        retValues[0] = Util.getShort(buf, index);
        index++;
      } else if (numBytes == 1) {
        index++;
        retValues[0] = (short)(buf[index] & (short)0x00FF);
      }else{
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
    } else {
      retValues[0] = (short)(buf[index] & (short)0x00FF);
    }
    index++;
    return index;
  }

  /**
   * Read the BER TLV object pointed by index. If TLV object is larger than the len of the buffer
   * then ISO7816.SW_WRONG_LENGTH exception is thrown.
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @param skip - if true then skip the receding 0xFFs or 0s
   * @param retValues The returned data of the TLV object.
   *  - retValues[0] - start index of TLV object
   *  - retValues[1] - tag id.
   *  - retValues[2] - tag length
   *  - retValues[3] = start index of TLV value field.
   * @return index pointing at start of the next byte following the end of TLV object.
   */
  public static short getNextTag(byte[] buf, short index, short len, boolean skip, short[] retValues){
    if(len == 0) return FiraSpecs.INVALID_VALUE;
    if(skip) {
      index = skipZerosAndFFs(buf, index, len);
    }
    retValues[0] = retValues[1]= retValues[2]=retValues[3]=0;
    short end = (short)(index + len);
    short tagStart = index;
    short tag;
    short tagLen;
    short tagValIndex;
    if(len == 0) return index;
    if(len < 0){
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    index = readBERTag(buf, index, len, retValues);
    tag = retValues[0];
    index = readBERLength(buf, index, len, retValues);
    tagLen = retValues[0];
    tagValIndex = index;
    index += tagLen;
    if(index > end) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    retValues[0] = tagStart;
    retValues[1] = tag;
    retValues[2] = tagLen;
    retValues[3] = tagValIndex;
    return index;
  }

  /**
   * Read the BER TLV object pointed by index and matching the tag in the buffer. If TLV object is
   * larger than the len of the buffer then ISO7816.SW_WRONG_LENGTH exception is thrown.
   * @param tag - desired tag id
   * @param buf - buffer of data
   * @param index - start index
   * @param len - length of the buffer
   * @param skip - if true then skip the receding 0xFFs and 0s.
   * @param retValues The returned data of the TLV object.
   *  - retValues[0] - start index of TLV object
   *  - retValues[1] - tag id.
   *  - retValues[2] - tag length
   *  - retValues[3] = start index of TLV value field.
   * @return index pointing at start of the next byte following the end of the desired TLV object.
   * If the tag is not present in the buffer than the FIRASpecs.INVALID_VALUE is returned
   */
  public static short getTag(short tag, byte[] buf, short index, short len, boolean skip,
      short[] retValues){
    if(len == 0) return FiraSpecs.INVALID_VALUE;
    short end = (short)(index + len);
    while(index < end){
      index = getNextTag(buf, index, (short)(end - index), skip, retValues);
      if(retValues[1] == tag){
        return index;
      }
    }
    return FiraSpecs.INVALID_VALUE;
  }

  public static short pushBerTagAndLength(byte[] buf, short index, short tag, short len){
    index = pushBERLength(buf,index, len);
    return pushBERTag(buf, index,tag);

  }
  public static short pushBERTag(byte[] buf, short index, short tag){
    if((short)(tag & (short) 0xFF00) == 0){
      index--;
      buf[index] = (byte)tag;
    }else{
      index--;
      buf[index] = (byte)(tag & 0xFF);
      index--;
      buf[index] = (byte)((tag >> 8) & 0xFF);
    }
    return index;
  }

  public static short pushBERLength(byte[] buf, short index, short len){
    if(len < 0x7F){
      index--;
      buf[index] = (byte) len;
    }else if(len > 127){
      if((short)(len & (short) 0xFF00) == 0){
        index--;
        buf[index]= (byte)(len & 0xFF);
        index--;
        buf[index] = (byte) 0x81;
      }else{
        index-=2;
        Util.setShort(buf, index, len);
        index--;
        buf[index] = (byte) 0x82;
      }
    }
    return index;
  }

  public static short pushByte(byte[] buf, short index, byte val){
    index--;
    buf[index]=val;
    return index;
  }

  public static short pushBytes(byte[] buf, short index, byte[] data, short start, short len){
    index -= len;
    if(len < 0){
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    Util.arrayCopyNonAtomic(data, start, buf, index,len);
    return index;
  }
  public static short pushBERTlv(byte[] buf, short index, short tag, byte[] data){
    return pushBERTlv(buf, index, tag, data, (short)0, (short)data.length);
  }
  public static short pushBERTlv(byte[] buf, short index, short tag, byte[] data, short start, short len){
    index = pushBytes(buf,index,data,start,len);
    index = pushBERLength(buf, index, len);
    return pushBERTag(buf,index,tag);
  }

  public static short push(byte[] buf, short index, short len,
      byte[] mem, short memIndex, short memLen, short[] retValues, short end){
    // Read the next tag
    short tagEnd = getNextTag(buf,index,len,true,retValues);
    if(tagEnd == FiraSpecs.INVALID_VALUE){
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    index = retValues[3];
    len = retValues[2];
    short tag = retValues[1];
    // search the memory
    short memEnd = getTag(tag,mem,memIndex,memLen,true,retValues);
    if(memEnd == FiraSpecs.INVALID_VALUE) {
      // If the memory does not have this tag
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    memIndex = retValues[3];
    memLen = retValues[2];
    if(len > 0){ // more child tags remain in input
      index = push(buf, index,len,mem,memIndex,memLen,retValues,end);
      return pushBerTagAndLength(buf,index,tag,(short)(end - index));
    }else{ // last tag
      return pushBERTlv(buf,end,tag,mem,memIndex,memLen);
    }
  }

  public static short pushTag(byte[] buf, short index, short len,
      byte[] mem, short memIndex, short memLen, short[] retValues, short end){
   // Read the next tag
    short tagEnd = getNextTag(buf,index,len,true,retValues);
    index = retValues[3];
    len = retValues[2];
    short tag = retValues[1];
    // search the memory
    short memEnd = getTag(tag,mem,memIndex,memLen,true,retValues);
    memIndex = retValues[3];
    memLen = retValues[2];
    // If tag is present and it is having a child tag then
    if(tagEnd != FiraSpecs.INVALID_VALUE && len > 0 && memEnd != FiraSpecs.INVALID_VALUE){
      //recurse to next level
      index = pushTag(buf, index,len,mem,memIndex,memEnd,retValues,end);
      // add this tag
      return pushBerTagAndLength(buf,index,tag,(short)(end - index));
    }else if(tagEnd == FiraSpecs.INVALID_VALUE){
      // If there is no next tag
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    } else if(memEnd == FiraSpecs.INVALID_VALUE) {
      // If the memory does not have this tag
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }else{
      // If it is the end of the input tree and if the mem has the tag then push it.
      return pushBERTlv(buf,end,tag,mem,memIndex,memLen);
    }
    return FiraSpecs.INVALID_VALUE;
  }

  public static short search(short parentTag, short tag, byte[] val, short valStart, short valLen,
      byte[] mem, short index, short len, short[] retValues) {
    short end = (short) (index + len); // end of the credentials.
    // Read the key sets one by one - index points to beginning of the key set and the end points to
    // end of all the key sets.
    FiraApplet.print(mem,index,len);
    while ( index != FiraSpecs.INVALID_VALUE && index < end) {
      // read the tag
      index = getNextTag(mem, index, (short)(end - index), false, retValues);
      // Is the tag parent tag or any tag.
      if (index != FiraSpecs.INVALID_VALUE &&
          (parentTag == FiraSpecs.INVALID_VALUE || parentTag == retValues[1])) {
        short curParentStart = retValues[0];
        short curParentTag = retValues[1];
        short curParentLen = retValues[2];
        short curParentVal = retValues[3];
        // Go inside the current tag
        // find the tag value in this tag
        short tagEnd = getTag(tag, mem, curParentVal, curParentLen, false, retValues);
        // Compare the returned value with the given value
        if (tagEnd != FiraSpecs.INVALID_VALUE && valLen == retValues[2] &&
            Util.arrayCompare(val, valStart, mem, retValues[3],valLen) == 0) {
          retValues[0] = curParentStart;
          retValues[1] = curParentTag;
          retValues[2] = curParentLen;
          retValues[3] = curParentVal;
          return index;
        }
      }
    }
    return FiraSpecs.INVALID_VALUE;
  }
  public static void print(byte[] buf, short start, short length) {
//    StringBuilder sb = new StringBuilder();
//    System.out.println("----");
//    for (int i = start; i < (start + length); i++) {
//      sb.append(String.format("%02X", buf[i]));
//    }
//    System.out.println(sb.toString());
  }

}
