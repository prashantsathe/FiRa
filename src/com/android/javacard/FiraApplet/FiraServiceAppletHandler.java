package com.android.javacard.FiraApplet;

import javacard.framework.AID;
import javacard.framework.JCSystem;

public class FiraServiceAppletHandler {
  private static final byte SERVICE_ID = (byte)0xFA;
  private FiRaServiceApplet appletRef;
  private AID appletId;
  private boolean[] reserved;

  public FiraServiceAppletHandler(byte[] buf, short inputStart, byte inputLen) {
    appletId = new AID(buf, inputStart, inputLen);
    appletRef = (FiRaServiceApplet) JCSystem.getAppletShareableInterfaceObject(appletId,SERVICE_ID);
    reserved = JCSystem.makeTransientBooleanArray((short)1,JCSystem.CLEAR_ON_RESET);
    reserved[0] = false;
  }

  public void delete(){
    appletId = null;
    appletRef = null;
    JCSystem.requestObjectDeletion();
  }

  //TODO The Fira Service Applet does not say what we have to pass in outBuffer, etc. as it is
  // reserved for future. We assume that null can be passed as buffer.
  public short init(byte[] oid, short index, short len){
    len = appletRef.processFiRaServiceCommand(oid, index, len,null,(short)0);
    reserved[0] = true;
    return len;
  }

  public boolean isReserved(){
    return reserved[0];
  }
  public void cleanUp(){
    reserved[0] = false;
    appletRef.processFiRaServiceCleanup();
  }

  public short getAppletId(byte[] buf, short index) {
    return appletId.getBytes(buf,index);
  }

  public boolean isAppletIdEquals(byte[] buf, short index, byte len){
    return appletId.equals(buf, index, len);
  }

  public short dispatch(byte[] buf, short cmdIndex, short cmdLen, byte[] outBuf, short outIndex) {
    return appletRef.processFiRaServiceCommand(buf,cmdIndex,cmdLen,outBuf,outIndex);
  }
}
