package com.android.javacard.FiraApplet;

import com.android.javacard.SecureChannels.FiraSecureChannel;
import com.android.javacard.SecureChannels.Scp;

public class FiraSCHandler {
  //TODO remove this later
  private static void setSlot(FiraAppletContext context){
    if(context.getSecureChannel() instanceof Scp && context.getSlot() == FiraSpecs.INVALID_VALUE){
      context.setRoot();
    }
    //else if(context.getSlot() == FIRASpecs.INVALID_VALUE) {
    //  context.setSlot((byte)1);
    //}
  }
  public  static short handleProtocolObject(byte[] buf, short index, short len, FiraAppletContext context){
    //TODO remove this later
    setSlot(context);
    FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
    return channel.handleProtocolObject(buf,index,len);
  }
  public  static short wrap(byte[] buf, short index, short len, FiraAppletContext context){
    FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
    return channel.wrap(buf, index,len);
  }
  public  static short unwrap(byte[] buf, short index, short len, FiraAppletContext context){
    FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
    return channel.unwrap(buf, index,len);
  }
  public static void terminate(FiraAppletContext context){
    FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
    channel.terminate();
  }

  // The secure channel will prepare select command
  public static short initiate(byte[] firaAppletAid, short start, short appletIdLen, byte[] buf,
      short index, short len, byte[] oidBuf, short oidStart, short oidEnd, FiraAppletContext context) {
    FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
    return channel.initiate(firaAppletAid, start, appletIdLen, oidBuf,oidStart , oidEnd, buf, index, len);
  }

  public static short getNotification(byte[] buf, short index, FiraAppletContext context, short[] retValues){
    byte eventId = (byte)context.getPendingEvent();
    short eventDataLen = 0;
    if(eventId != FiraAppletContext.EVENT_INVALID && eventId != FiraAppletContext.EVENT_SECURE){
      FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
      eventDataLen = channel.getEventData(eventId, buf, index);
    }
    retValues[0] = eventId;
    return eventDataLen;
  }

  public static boolean isSecure(FiraAppletContext context){
    boolean ret = false;
    if(context.getPendingEvent() == FiraAppletContext.EVENT_SECURE) {
      context.clearPendingEvent();
      ret = true;
    }
    return ret;
  }

  public static byte getProtocolType(FiraAppletContext context) {
    FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
    return channel.getProtocolType();
  }

  public static short generateRDS(byte[] buf, short index, short len, FiraAppletContext context){
    FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
    //TODO Extended options not supported
    return channel.generateRds(buf, index, len, null, (short)0, (short)0,
        context.isDefaultKeyGeneration(), context.isSessionKeyUsedForDerivation());
  }
}
