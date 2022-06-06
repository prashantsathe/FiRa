package com.android.javacard.FiraApplet;

import com.android.javacard.SecureChannels.FiraClientContext;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * This class provides channel specific context - selected slot, state and any state specific data.
 * There will be one instance of this class per logical channel.
 */
public class FiraAppletContext extends FiraClientContext {
  // Total number of logical channels supported - each will have a context
  public static final byte IMPL_MAX_LOGICAL_CHANNELS = 20;

  // Attribute offsets
  private static final byte SLOT = 0;
  private static final byte REMOTE_CHANNEL_STATE = 1;
  private static final byte LOCAL_CHANNEL_STATE = 2;
  private static final byte OPERATION_STATE = 3;
  private static final byte EXTENDED_OPTIONS_BYTE_1 = 4;
  private static final byte EXTENDED_OPTIONS_BYTE_2 = 5;
  private static final byte EVENT = 6;
  private static final byte APPLET_REF = 7;
  private static final byte ATTRIBUTES_COUNT = 8;

  // Extended Options masks
  public static final byte EXT_OPTIONS_TERMINATE = (byte)0x80;
  public static final byte EXT_OPTIONS_PRIVACY = (short)0x40;
  public static final byte EXT_OPTIONS_SESSION_KEY = (byte)0x80;
  public static final byte EXT_OPTIONS_DERIVE_KEY = (byte)0xA0;

  // Remote Secure Channel sub-states - for SC1 and SC2
  public static final byte REMOTE_UNSECURE = (byte)0;
  public static final byte REMOTE_SECURE = (byte)0x02;

  // Local Secure Channel sub-states - for SCP11c
  public static final byte LOCAL_UNSECURE = (byte)0x00;
  public static final byte LOCAL_SECURE = (byte)0x01;

  //Asynchronous Operation states
  public static final byte OP_IDLE = (byte)0;
  public static final byte OP_TUNNEL_ACTIVE = (byte)1;

  //Asynchronous sub-operation state for tunneled command
  public static final byte OP_TERMINATE_SESSION = (byte) 0x40;
  public static final byte OP_STATE_MASK = (byte)0x0F;

  // Context table - one per logical channel
  private static Object[] contexts;
  private static short[] retValues;

  // instance attributes
  private byte[] attributes;
  private Object[] dataCache;
  private Object[] secureChannel;

  private FiraAppletContext(){
    attributes = JCSystem.makeTransientByteArray((short)ATTRIBUTES_COUNT, JCSystem.CLEAR_ON_RESET);
    dataCache = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_RESET);
    secureChannel = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_RESET);
    retValues = JCSystem.makeTransientShortArray((short)5, JCSystem.CLEAR_ON_RESET);
    reset();
  }

  public void setSecureChannel(Object channel){
    secureChannel[0] = channel;
  }
  public Object getSecureChannel(){
    return secureChannel[0];
  }
  public void reset(){
    attributes[SLOT] = FiraSpecs.INVALID_VALUE;
    attributes[LOCAL_CHANNEL_STATE] = LOCAL_UNSECURE;
    attributes[REMOTE_CHANNEL_STATE] = REMOTE_UNSECURE;
    attributes[OPERATION_STATE] = OP_IDLE;
    attributes[EXTENDED_OPTIONS_BYTE_1] = 0;
    attributes[EXTENDED_OPTIONS_BYTE_2] = 0;
    attributes[EVENT] = FiraClientContext.EVENT_INVALID;
    attributes[APPLET_REF] = FiraSpecs.INVALID_VALUE;
  }

  public static void init(){
    byte channels = IMPL_MAX_LOGICAL_CHANNELS;
    contexts = JCSystem.makeTransientObjectArray(channels, JCSystem.CLEAR_ON_RESET);
    while(channels>0){
      channels--;
      contexts[channels] = new FiraAppletContext();
    }
  }

  public static FiraAppletContext getContext(short channel){
    return (FiraAppletContext)contexts[channel];
  }

  public byte getAppletRef(){
    return attributes[APPLET_REF];
  }

  public short setAppletRef(byte appletRef){
    return attributes[APPLET_REF] = appletRef;
  }

  public short getSlot() {
    if(attributes[SLOT] < 0) {
      return FiraSpecs.INVALID_VALUE;
    }else {
      return attributes[SLOT];
    }
  }

  public boolean isRoot(){
    return getSlot() == FiraRepository.ROOT_SLOT;
  }

  public void setRoot(){
    attributes[SLOT] = FiraRepository.ROOT_SLOT;
  }

  public void clearRoot(){
    attributes[SLOT] = FiraSpecs.INVALID_VALUE;
  }

  public void setSlot(byte slot){
    attributes[SLOT] = slot;
    FiraRepository.selectAdf(slot);
  }

  public void clearSlot(){
    if(attributes[SLOT] != FiraSpecs.INVALID_VALUE){
      FiraRepository.deselectAdf(attributes[SLOT]);
    }
    attributes[SLOT] = FiraSpecs.INVALID_VALUE;
  }

  public boolean isLocalSecure() {
    return attributes[LOCAL_CHANNEL_STATE] == LOCAL_SECURE ;
  }

  public boolean isLocalUnSecure() {
    return attributes[LOCAL_CHANNEL_STATE] == LOCAL_UNSECURE;
  }

  public boolean isRemoteUnSecure() {
    return attributes[REMOTE_CHANNEL_STATE] == REMOTE_UNSECURE;
  }

  public boolean isRemoteSecure() {
    return attributes[REMOTE_CHANNEL_STATE] == REMOTE_SECURE;
  }

  public short getLocalChannelState(){
    return attributes[LOCAL_CHANNEL_STATE];
  }

  public short getRemoteChannelState(){
    return attributes[REMOTE_CHANNEL_STATE];
  }
  public void setLocalSecureState(byte secureState){
    attributes[LOCAL_CHANNEL_STATE] = secureState;
  }

  public void setRemoteSecureState(byte secureState){
    attributes[REMOTE_CHANNEL_STATE] = secureState;
  }

  public void setOpState(byte opState){
    attributes[OPERATION_STATE] = (byte)(attributes[OPERATION_STATE] | opState);
  }

  public byte[] getDataCache() {
    return (byte[])dataCache[0];
  }

  public void associateDataCache(byte[] cache) {
    dataCache[0] = cache;
  }

  public short getOpState() {
    return (byte)(attributes[OPERATION_STATE] & OP_STATE_MASK);
  }
  public void clearOperationState(){
    attributes[OPERATION_STATE] = OP_IDLE;
  }
  public void clearTerminateSessionOpState(){
    attributes[OPERATION_STATE] = (byte) (attributes[OPERATION_STATE] & (byte)0x00BF);
  }
  public void setExtOptions(short extOpts){
    attributes[EXTENDED_OPTIONS_BYTE_1] = (byte)((extOpts & (short)0xFF00) >> 8);
    attributes[EXTENDED_OPTIONS_BYTE_2] = (byte)(extOpts & (short)0x00FF);
  }

  public boolean isAutoTerminate(){
    return (attributes[EXTENDED_OPTIONS_BYTE_1] & EXT_OPTIONS_TERMINATE) != 0;
  }

  public boolean isPrivacyEnforced(){
    return (attributes[EXTENDED_OPTIONS_BYTE_1] & EXT_OPTIONS_PRIVACY) != 0;
  }

  public boolean isDefaultKeyGeneration(){
    return (attributes[EXTENDED_OPTIONS_BYTE_2] & EXT_OPTIONS_SESSION_KEY) == 0;
  }

  public boolean isSessionKeyUsedForDerivation(){
    return (attributes[EXTENDED_OPTIONS_BYTE_2] & EXT_OPTIONS_DERIVE_KEY) != 0;
  }

  // Input is OId. Returns set of KVNs if the adf identified by the oid can be selected else it
  // returns null.
  //TODO This method is implemented based on an understanding that just like initiator the
  // responder may or may not have static adf slot and the oid received in select adf command may
  // refer the swapped dynamic slot adf. There are two cases: first case is that oid is found
  // in static slot - in this case the context must not have any selected slot. The second case is
  // that context has dynamic slot i.e. swapped in adf and selected adf is routed to that. In this
  // case the slot in the context must match that in select adf.

  public boolean selectAdf(byte[] oidBuf, short start, short len) {
    byte slot = FiraRepository.getSlotUsingOid(oidBuf, start, len);
    if (slot != FiraSpecs.INVALID_VALUE && getSlot() == FiraSpecs.INVALID_VALUE) {
        setSlot(slot);
        return true;
    }
    return slot != FiraSpecs.INVALID_VALUE && slot == getSlot();
  }

  public static void print(byte[] buf, short start, short length) {
//    StringBuilder sb = new StringBuilder();
//    System.out.println("----");
//    for (int i = start; i < (start + length); i++) {
//      sb.append(String.format("%02X", buf[i]));
//    }
//    System.out.println(sb.toString());
  }


  public short getSelectedKvn(byte kvnType, byte[] buf, short index) {
    byte[] mem = FiraRepository.getSlotData(FiraSpecs.TAG_FIRA_SC_CRED, (byte) getSlot(), retValues);
    print(mem,retValues[1],retValues[2]);
    short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_CRED, mem, retValues[1], retValues[2],
        false, retValues);
    short start = retValues[3];
    short len = retValues[2];
    print(mem, start, len);
    switch(kvnType){
      case PRIVACY_KEY_SET:
        buf[index]= (byte) FiraSpecs.VAL_SC1_PRIVACY_KEY_SET;
        tagEnd = FiraUtil.search(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_KEY_SET, FiraSpecs.TAG_FIRA_SC_CH_ID,
            buf,index,(short)1,mem,start,len,retValues);
        if(tagEnd == FiraSpecs.INVALID_VALUE){
          buf[index]= (byte) FiraSpecs.VAL_SC2_PRIVACY_KEY_SET;
          tagEnd = FiraUtil.search(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_KEY_SET, FiraSpecs.TAG_FIRA_SC_CH_ID,
              buf,index,(short)1,mem,start,len,retValues);
        }
        break;
      case SC_KEY_SET:
        tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_KEY_SET, mem, start, len, true, retValues);
        if (tagEnd == FiraSpecs.INVALID_VALUE) {
          tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_ASYMMETRIC_KEY_SET, mem, start, len, true, retValues);
        }
        break;
      case BASE_KEY_SET:
        tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_BASE_KEY, mem, start, len, true, retValues);
        break;
      case UWB_ROOT_KEY_SET:
        tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_UWB_RANGING_ROOT_KEY, mem, start, len, true, retValues);
        break;

    }
    if(tagEnd == FiraSpecs.INVALID_VALUE){
      return 0;
    }else{
      Util.arrayCopyNonAtomic(mem,retValues[0],buf,index,(short)(tagEnd - retValues[0]));
      return (short)(tagEnd - retValues[0]);
    }
  }

  // Input is key set kvn and output is key set. If the key set is not found then  it
  // returns INVALID_VAL else key set is copied in the buf starting at index and returns the length
  // of the key set. Key set is copied in BER TLV format, starting with key set tag as defined in
  // FiraApplet Specifications.

  public short getKeySet(short kvn, byte[] buf, short index) {
    byte[] mem = FiraRepository.getSlotData(FiraSpecs.TAG_FIRA_SC_CRED, (byte) getSlot(), retValues);
    buf[index] = (byte) kvn;
    short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_CRED, mem, retValues[1], retValues[2],
        false, retValues);
    short start = retValues[3];
    short len = retValues[2];
    tagEnd = FiraUtil.search(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_KEY_SET, FiraSpecs.TAG_FIRA_SC_KVN,
        buf, index, (short) 1, mem, start, len, retValues);
    if (tagEnd == FiraSpecs.INVALID_VALUE) {
      tagEnd = FiraUtil.search(FiraSpecs.TAG_FIRA_SC_ASYMMETRIC_KEY_SET, FiraSpecs.TAG_FIRA_SC_KVN,
          buf, index, (short) 1, mem, start, len, retValues);
      if(tagEnd == FiraSpecs.INVALID_VALUE){
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
     }
    }
    Util.arrayCopyNonAtomic(mem, retValues[0], buf,index,(short)(tagEnd - retValues[0]));
    print(buf,index,(short)(tagEnd - retValues[0]));
    return retValues[2];
  }


  public short getPendingEvent() {
    return attributes[EVENT];
  }


  public void signal(short eventId) {
    attributes[EVENT] = (byte) eventId;
  }

  public void clearPendingEvent(){
    attributes[EVENT] = EVENT_INVALID;
  }

  public void enableTerminateSessionOpState(){
    attributes[OPERATION_STATE] = (byte)(attributes[OPERATION_STATE] | OP_TERMINATE_SESSION);
  }
  public boolean isTerminateSession(){
    return (byte)(attributes[OPERATION_STATE] & OP_TERMINATE_SESSION) != 0;
  }
/*
  public static final byte LOCAL_SELECTED = 20;
  public static final byte LOCAL_ADF_SELECTED = 21;
  public static final byte LOCAL_AUTH1_DONE = 22;
  public static final byte INIT_TRANSACTION_STARTED = 23;
  public static final byte REMOTE_SELECTED = 24;
  public static final byte REMOTE_ADF_SELECTED = 25;
  public static final byte REMOTE_AUTH1_DONE = 26;
  private static final byte LOCAL_STATE_MASK = 0x01;
  private static final byte REMOTE_STATE_MASK = 0x02;
  public static final byte PSO_DONE = 10;
  public static final byte AUTH_DONE = 11;
  public static final byte INIT_TRANSACTION_ACTIVE = 2;
  public static final byte PUT_DATA_ACTIVE = 3;
  public static final byte GET_DATA_ACTIVE = 4;
  public static final byte TERMINATE_SESSION_ACTIVE = 5;
*/

}
