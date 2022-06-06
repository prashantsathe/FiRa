package com.android.javacard.FiraApplet;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
import org.firaconsortium.sus.SecureUwbService;

import com.android.javacard.SecureChannels.FiraSecureChannel;

public class FiraApplet extends Applet implements AppletEvent, MultiSelectable, ExtendedLength {

  // TODO Change the applet id
  //  Also this FiraApplet Applet is not suppose to have more then one instance
  final static byte[] APPLET_OID = {0x06, 0x0A, 0x0A, 0, 0, 0, 0, 0, 0, 0, 6, 2};
  final static byte[] APPLET_AID = {0x0A, 0, 0, 0, 0, 0, 0, 0, 6, 2};
  final static short IMPL_SCRATCH_PAD_MAX_SIZE = 256;
  final static short IMPL_APDU_BUFFER_MAX_SIZE = 5000;
  static final byte DATA_CACHE_HEADER_LEN = 2;

  // Types
  private static final byte BYTES = 0;
  private static final byte ENUM = 1;
  private static final byte STRUCTURE = 2;

  // Flags
  private static final byte NUM_OF_FLAGS = 1;
  private static final byte DATA_CACHE_IN_USE = 0;

  private static final byte P1_ADD_SERVICE_APPLET = 1;
  private static final byte P1_REMOVE_SERVICE_APPLET = 2;
  private static final byte P1_ADD_PA_CRED = 1;
  private static final byte P1_REMOVE_PA_CRED = 2;

  private static AESKey masterKey;
  private static short[] retValues;
  private static boolean[] flags;
  private static byte[] dataCache;
  private static FiraServiceAppletHandler[] serviceApplet;

  private static SecureUwbService susApplet;
  private static AID susAid;
  /**
   * Constructor.
   */
  public FiraApplet() {
    serviceApplet = new FiraServiceAppletHandler[FiraSpecs.IMPL_MAX_SERVICE_APPLETS];
    susAid = new AID(FiraSpecs.SUS_APPLET_AID, (short)0, (byte) FiraSpecs.SUS_APPLET_AID.length);
    susApplet = (SecureUwbService) JCSystem.getAppletShareableInterfaceObject(susAid,
        SecureUwbService.SERVICE_ID);
    retValues = JCSystem.makeTransientShortArray((short) 5, JCSystem.CLEAR_ON_DESELECT);

    //Following memory is used mainly for store data and manage adf commands.
    //TODO determine whether we require clear on reset or clear on deselect.
    dataCache = JCSystem.makeTransientByteArray(
        (short) (FiraSpecs.IMPL_TRANSIENT_ADF_SIZE + FiraSpecs.IMPL_PERSISTENT_ADF_SIZE),
        JCSystem.CLEAR_ON_DESELECT);
    flags = JCSystem.makeTransientBooleanArray(NUM_OF_FLAGS, JCSystem.CLEAR_ON_DESELECT);
    flags[DATA_CACHE_IN_USE] = false;

    // Create Master Key used for Import ADF.
    //TODO make master key upgradeable.
    masterKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, false);
    randomNumber(dataCache, (short) 0, (short) 16);
    masterKey.setKey(dataCache, (short) 0);
    resetDataCache();
    FiraAppletContext.init();
    FiraRepository.init();
  }

  private void randomNumber(byte[] buf, short index, short len) {
    //TODO change to RandomData.oneShot
    RandomData rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    rng.nextBytes(buf, index, len);
  }

  /**
   * @return True if the data cache is free,
   */
  private static boolean isDataCacheFree() {
    return !flags[DATA_CACHE_IN_USE];
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new FiraApplet().register();
  }

  /**
   * Throw exception if the contest is not local and secure.
   */
  private void assertLocalSecure(FiraAppletContext context) {
    // TODO remove the following - for testing
//    context.setLocalSecureState(Context.LOCAL_SECURE);

    if (!context.isLocalSecure()) {
      ISOException.throwIt(FiraSpecs.COND_NOT_SATISFIED);
    }
  }

  /**
   * Throw exception if the contest is not remote and secure.
   */
  private void assertRemoteSecure(FiraAppletContext context) {
    // TODO remove the following - for testing
//    context.setRemoteSecureState(Context.REMOTE_SECURE);
    if (!context.isRemoteSecure()) {
      ISOException.throwIt(FiraSpecs.COND_NOT_SATISFIED);
    }
  }

  /**
   * Throw exception if the contest is not remote and secure.
   */
  private void assertRemoteUnSecure(FiraAppletContext context) {
    // TODO remove the following - for testing
//    context.setRemoteSecureState(Context.REMOTE_UNSECURE);
    if (context.isRemoteSecure()) {
      ISOException.throwIt(FiraSpecs.COND_NOT_SATISFIED);
    }
  }

  /**
   * Throw exception if the contest is not local and unsecure.
   */
  private void assertLocalUnSecure(FiraAppletContext context) {
    // TODO remove the following - for testing
//    context.setLocalSecureState(Context.LOCAL_UNSECURE);
    if (!context.isLocalUnSecure()) {
      ISOException.throwIt(FiraSpecs.COND_NOT_SATISFIED);
    }
  }

  private static void resetDataCache() {
    flags[DATA_CACHE_IN_USE] = false;
    Util.arrayFillNonAtomic(dataCache, (short) 0, (short) dataCache.length, (byte) 0);
  }

  private static void reserveDataCache() {
    if (!isDataCacheFree()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    flags[DATA_CACHE_IN_USE] = true;
  }

  private static void addToCache(byte[] buf, short start, short len) {
    //First two bytes is the length of the stored data.
    short dataLen = Util.getShort(dataCache, (short) 0);
    if ((short) (dataLen + len) > (short) dataCache.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    Util.arrayCopyNonAtomic(buf, start, dataCache, (short) (DATA_CACHE_HEADER_LEN + dataLen), len);
    Util.setShort(dataCache, (short) 0, (short) (dataLen + len));
  }


  public void process(APDU apdu) throws ISOException {
    // If this is an APDU to select this applet then just return
    if (apdu.isISOInterindustryCLA() && selectingApplet()) {
      // TODO confirm whether we have the same select protocol for local and remote selects.
      return;
    }
    // The applet uses extended apdu as its heap memory for processing.
    // TODO this is major assumption which needs to be supported for all the APDU
    //  including scp11c.
    if (apdu.getBuffer().length < IMPL_APDU_BUFFER_MAX_SIZE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Applet is multi selectable, get the context of the logical channel used in the selection.
    FiraAppletContext context = FiraAppletContext.getContext(getChannel(apdu));
    // process the instruction.
    switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
      case FiraSpecs.INS_PROVISION_SD_CREDENTIALS:
        processProcessSDCredentials(apdu, context);
        break;
      case FiraSpecs.INS_PROVISION_PA_CREDENTIALS:
        processProcessPACredentials(apdu, context);
        break;
      case FiraSpecs.INS_PROVISION_SERVICE_APPLET:
        processProvisionServiceApplet(apdu, context);
        break;
      case FiraSpecs.INS_CREATE_ADF:
        processCreateADFCmd(apdu, context);
        break;
      case FiraSpecs.INS_MANAGE_ADF:
        processManageADFCmd(apdu, context);
        break;
      case FiraSpecs.INS_DELETE_ADF:
        processDeleteAdfCmd(apdu, context);
        break;
      case FiraSpecs.INS_IMPORT_ADF:
        processImportADFCmd(apdu, context);
        break;
      case FiraSpecs.INS_SWAP_ADF:
        processSwapADFCmd(apdu, context);
        break;
      case FiraSpecs.INS_INITIATE_TRANSACTION:
        processInitTransaction(apdu, context);
        break;
      case FiraSpecs.INS_DISPATCH:
        processDispatchCmd(apdu, context);
        break;
      case FiraSpecs.INS_PUT_DATA:
        processPutDataCmd(apdu, context);
        break;
      case FiraSpecs.INS_TUNNEL:
        processTunnelCmd(apdu, context);
        break;
      case FiraSpecs.INS_GET_DATA:
        processGetDataCmd(apdu, context);
        break;
      case FiraSpecs.INS_PERFORM_SECURITY_OPERATION:
      case FiraSpecs.INS_MUTUAL_AUTH:
        processScp11cCmd(apdu, context);
        break;
      case FiraSpecs.INS_SELECT_ADF:
        processSelectAdf(apdu, context);
        break;
//        case FIRASpecs.INS_STORE_DATA:
//          processStoreDataCmd(apdu, context);
//          break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
    }
  }

  private void processProvisionServiceApplet(APDU apdu, FiraAppletContext context) {
    assertLocalUnSecure(context); // Change this if secure state required
    assertUnSecureChannels(apdu);
    apdu.setIncomingAndReceive();
    byte[] buf = apdu.getBuffer();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    switch (buf[ISO7816.OFFSET_P1]){
      case P1_ADD_SERVICE_APPLET:
        plugInServiceApplet(buf, inputStart, inputLen);
        break;
      case P1_REMOVE_SERVICE_APPLET:
        plugOutServiceApplet(buf, inputStart, inputLen);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
      }
  }

  private void plugOutServiceApplet(byte[] buf, short inputStart, short inputLen) {
    short index = getServiceApplet(buf, inputStart, (byte)inputLen);
    if(index == FiraSpecs.INVALID_VALUE){
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    serviceApplet[index].delete();
    serviceApplet[index] = null;
    JCSystem.requestObjectDeletion();
  }

  private void plugInServiceApplet(byte[] buf, short inputStart, short inputLen) {
    if(getServiceApplet(buf, inputStart, (byte)inputLen) != FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    byte len = (byte)serviceApplet.length;
    byte index = 0;
    while(index < len){
      if(serviceApplet[index] == null){
        serviceApplet[index] = new FiraServiceAppletHandler(buf, inputStart, (byte)inputLen);
        return;
      }
      index++;
    }
    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
  }

  private byte getServiceApplet(byte[] buf, short inputStart, byte inputLen) {
    byte len = (byte)serviceApplet.length;
    byte index = 0;
    while(index < len){
      if(serviceApplet[index] != null &&
          serviceApplet[index].isAppletIdEquals(buf, inputStart,inputLen)){
          return index;
      }
      index++;
    }
    return FiraSpecs.INVALID_VALUE;
  }

  //TODO this command will be used to select the adf with local connection. It is not meant to
  // establish any SC connection as per FIRA Specs. This leads to confusion as to which version of
  // SELECT ADF will be sent - woule be be SC1 or SC2. Also number of OIDs can by more then one.
  // So, we can select one out of many. This will then also be sent to remote during init
  // transaction? It does not make sense then why there can be multiple OIDs in both SELECT ADF
  // and INIT TRANSACTION. This is very ambiguous.
  // We assume here that SC1 version of SELECT ADF command will be sent by Framework.
  // We assume that privacy selection will never be used for local connection.
  // The response will include 0 as random data2 for the response and diversitification data will
  // be 0 because this will never be used further.
  private void processSelectAdf(APDU apdu, FiraAppletContext context) {
    // TODO We assume that this will come in either local secure or unsecure state. But there should
    //  not be any remote channel.
    assertRemoteUnSecure(context);
    // There should not be already selected slot
    if (context.getSlot() != FiraSpecs.INVALID_VALUE &&
        context.getSlot() != FiraRepository.ROOT_SLOT) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    apdu.setIncomingAndReceive();
    byte[] buf = apdu.getBuffer();
    //TODO current implementation does not support privacy selection for local connections
    // P1 = 4 or 1, P2 = 0
    if (buf[ISO7816.OFFSET_P1] != 4 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Receive all
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    // If local secure state then unwrap
    if(context.isLocalSecure()){
      unwrap(buf, inputStart, inputLen, context);
    }
    // Select first OID in the list of OIDs.
    short randomDataEnd = FiraUtil.getTag(FiraSpecs.TAG_RANDOM_DATA_1_2, buf, inputStart, inputLen, true, retValues);
    if (randomDataEnd == FiraSpecs.INVALID_VALUE || retValues[2] != (byte)16) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short randStart = retValues[0];
    short oidEnd = FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true, retValues);
    if (oidEnd == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    // Get the slot for the OID
    short oidStart = retValues[0];
    byte slot = FiraRepository.getSlot(buf, oidStart, (short) (oidEnd - oidStart));
    if (slot == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(FiraSpecs.OID_ALREADY_PRESENT);
    }
    //Set the slot in the current context.
    context.setSlot(slot);
    if(context.isLocalSecure()){
      unwrap(buf, inputStart, inputLen, context);
    }
    inputStart = (randomDataEnd > oidEnd)?randomDataEnd : oidEnd;
    // make and return response
    short end = makeSelectResponse(buf, oidStart, oidEnd, randStart, randomDataEnd, inputStart);
    inputLen = (short)(end - inputStart);
    apdu.setOutgoing();
    apdu.setOutgoingLength(inputLen);
    apdu.sendBytesLong(buf, inputStart, inputLen);
  }

  private short makeSelectResponse(byte[] buf, short oidStart, short oidEnd, short randStart,
      short randEnd, short index) {
    byte[] mem = FiraRepository.getAppletData(FiraSpecs.TAG_DEVICE_UID,retValues);
    if(mem == null){
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short deviceUidEnd = FiraUtil.getTag(FiraSpecs.TAG_DEVICE_UID,mem,retValues[1],retValues[2],true,retValues);
    if(deviceUidEnd == FiraSpecs.INVALID_VALUE){
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short deviceUidStart = retValues[3];
    short deviceUidLen = retValues[2];
    short oidLen = (short)(oidEnd - oidStart);
    short randLen = (short)(randEnd - randStart);
    index = Util.arrayCopyNonAtomic(FiraSpecs.SELECT_ADF_ALGORITHM_INFO,(short)0,buf, index,
        (short) FiraSpecs.SELECT_ADF_ALGORITHM_INFO.length);
    index = Util.arrayCopyNonAtomic(buf,oidStart,buf, index, oidLen);
    buf[index++] = (byte) FiraSpecs.TAG_DIVERSIFIER;
    buf[index++] = (byte) deviceUidLen;
    index = Util.arrayCopyNonAtomic(mem,deviceUidStart,buf, index, deviceUidLen);
    index = Util.arrayCopyNonAtomic(buf,randStart,buf, index, randLen);
    return index;
  }

  private void processScp11cCmd(APDU apdu, FiraAppletContext context) {
    assertLocalUnSecure(context);
    assertRemoteUnSecure(context);
    if (context.getSecureChannel() == null) {
      context.setSecureChannel(
          FiraSecureChannel.create(FiraSecureChannel.FIRA_SCP11c_PROTOCOL, context));
    }
    apdu.setIncomingAndReceive();
    byte[] buf = apdu.getBuffer();
    short index = apdu.getOffsetCdata();
    short len = (short) apdu.getIncomingLength();
    len = FiraSCHandler.handleProtocolObject(
        buf, (short)0, (short)(len+ISO7816.OFFSET_EXT_CDATA), context);
    if (FiraSCHandler.isSecure(context)) {
      context.setLocalSecureState(FiraAppletContext.LOCAL_SECURE);
    }
    apdu.setOutgoing();
    apdu.setOutgoingLength(len);
    apdu.sendBytesLong(buf, index, len);
  }

  /*
  private void processStoreDataCmd(APDU apdu, Context context) {
  }
*/

  // TODO For JCOP this should just return apdu.getChannel()
  private byte getChannel(APDU apdu) {
    short cla = (short) (apdu.getBuffer()[ISO7816.OFFSET_CLA] & 0x00FF);
    if (cla >= (short)0x00E0 && cla <= (short)0x00EF) {
      return (byte) ((cla - (short)0xE0) + 4);
    } else if (cla >= (short)0x00C0 && cla <= (short)0x00CF) {
      return (byte) ((cla - (short)0xC0) + 4);
    } else if (cla >= (short)0x0084 && cla <= (short)0x0087) {
      return (byte) (cla - (short)0x84);
    } else { //if(cla >= 0x80 && cla <= 83)
      return (byte) (cla - (short)0x80);
    }
  }

  // This command is not specified in Fira but it is implied that it can be used to terminate session
  // (for terminating dangling sessions!)and to set root level controlee info.
  // Also the assumption in case the controlee info is set, it should contain all the information
  // i.e. capability and regulatory info. Else only the last put data will remain.
  // Also it is not clear whether get data and/or put data can be used with local secure context?
  // If not then how can Fira FW get sensitive data fro local FiraApplet Applet?
  // Does controlee info and session data considered to be sensitive data? We assume that this is
  // considered a sensitive info because otherwise there is no need to have secure channel to
  // tunnel the relevant commands.
  // TODO Confirm whether this is correct approach. The specs seems to be like a design specs and
  //  would require a reference implementation to understand the prescriptive interpretation.
  private void processPutDataCmd(APDU apdu, FiraAppletContext context) {
    // TODO we assume that this command can be used both in local secure and remote secure cases.
    //  In local secure case this command will be used to modify the root level adf, etc.
    //  In remote secure case this command will be used to terminate local session.
    //  Note: Context cannot have both local secure and remote secure at the same time.

    if ((context.isRemoteUnSecure() && context.isLocalUnSecure()) ||
        // local or remotely secure instruction
        (context.isRemoteSecure() && context.getSlot()
            == FiraSpecs.INVALID_VALUE) // remote secure must have selected slot
    ) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // If local secure then always use root slot is none selected.
    if (context.isLocalSecure() && context.getSlot() == FiraSpecs.INVALID_VALUE) {
      context.setRoot();
    }
    byte[] buf = apdu.getBuffer();
    // P1 = 4 or 1, P2 = 0
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    // Receive all
    apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    unwrap(buf, inputStart, inputLen, context);
    assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_LOCAL_PUT_DATA, true,
        buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    inputLen = processPutDataCmd(buf, inputStart, inputLen, context);
    print(buf, inputStart, inputLen);
    // There is no response data.
  }

  // TODO Assumption is that TUNNEL command is local unsecure, however it should only be processed if
  //  there is an existing remote secure channel. Also, assumption is that as extended APDUs are
  //  used hence Lc will be always 3 bytes - this matters in Dispatch Cmd.
  public void processTunnelCmd(APDU apdu, FiraAppletContext context) {
    assertRemoteSecure(context);
    if (context.getOpState() != FiraAppletContext.OP_IDLE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    byte[] buf = apdu.getBuffer();
    // P1 = 0 or 1, P2 = 0
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Receive all
    apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    // decode
    assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_TUNNEL,
        true, buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    // Read the proprietary command template tag
    FiraUtil.getNextTag(buf, inputStart, inputLen, true, retValues);
    // read the child tag i.e. proprietary command data of the proprietary tag
    // retValue[3] is the value and retValues[2] is the length of the value
    FiraUtil.getNextTag(buf, retValues[3], retValues[2], true, retValues);
    // Pass the value to the expected command
    inputStart = retValues[3];
    inputLen = retValues[2];
    // Check whether there is a "terminate session" command.
    if(isTerminateSession(buf, inputStart,inputLen)){
      context.enableTerminateSessionOpState();
    }
    // wrap it
    wrap(buf, inputStart, inputLen, context);
    // create dispatch response
    print(buf, inputStart, inputLen);
    inputStart = pushDispatchResponse(buf, inputStart, inputLen,
        FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER, FiraSpecs.INVALID_VALUE,
        null, FiraSpecs.INVALID_VALUE, (short) 0, retValues);
    inputLen = retValues[0];
    print(buf,inputStart,inputLen);
    context.setOpState(FiraAppletContext.OP_TUNNEL_ACTIVE);
    apdu.setOutgoing();
    apdu.setOutgoingLength(inputLen);
    apdu.sendBytesLong(buf, inputStart, inputLen);
  }

  private boolean isTerminateSession(byte[] buf, short inputStart, short inputLen) {
    //The input must have put apdu command
    short ins = buf[(short) (inputStart + ISO7816.OFFSET_INS)];
    if (ins != FiraSpecs.INS_PUT_DATA) {
      return false;
    }
    // TODO Only extended apdu are supported
    if (buf[(short) (inputStart + ISO7816.OFFSET_LC)] != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    inputLen = Util.getShort(buf, (short) (inputStart + ISO7816.OFFSET_LC + (short)1));
    inputStart += ISO7816.OFFSET_EXT_CDATA;
    assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_REMOTE_PUT_DATA,
        true, buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    if(FiraUtil.getTag(FiraSpecs.TAG_TERMINATE_SESSION,
        buf, inputStart, inputLen,true,retValues) == FiraSpecs.INVALID_VALUE){
      return false;
    }
    return true;
  }

  // Assumption is that DISPATCH COMMAND is not encrypted i.e. 0x70 and 0x71 tags are in clear text
  // the GET DATA, PUT DATA will be encrypted as part of 0x81 tag.
  private void processDispatchCmd(APDU apdu, FiraAppletContext context) {
    // Dispatch command must be local un-secure
    assertLocalUnSecure(context);
    byte[] buf = apdu.getBuffer();
    // P1 = 0 or 1, P2 = 0
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Receive all
    apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    // decode
    assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_DISPATCH_CMD,
        true, buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    // Read the proprietary command template tag
    short tagEnd = FiraUtil.getNextTag(buf, inputStart, inputLen, true, retValues);
    // read the child tag i.e. proprietary command data of the proprietary tag
    // retValue[3] is the value and retValues[2] is the length of the value
    tagEnd = FiraUtil.getNextTag(buf, retValues[3], retValues[2], true, retValues);
    // Pass the value to the expected command
    inputStart = retValues[3];
    inputLen = retValues[2];
    // The dispatch command can come during remote secure and unsecure state.
    switch (context.getRemoteChannelState()) {
      case FiraAppletContext.REMOTE_UNSECURE:
        inputStart = dispatchUnsecure(buf, inputStart, inputLen, context, retValues);
        if (FiraSCHandler.isSecure(context)) {
          context.setRemoteSecureState(FiraAppletContext.REMOTE_SECURE);
        }
        break;
      case FiraAppletContext.REMOTE_SECURE:
        // Multiple commands/responses can come in this state, and they will be encrypted.
        unwrap(buf, inputStart, inputLen, context);
        inputStart = dispatchSecure(buf, inputStart, inputLen, context, retValues);
        wrap(buf, inputStart, retValues[0], context);
        break;
    }
    ;
    print(buf, inputStart, retValues[0]);
    apdu.setOutgoing();
    apdu.setOutgoingLength(retValues[0]);
    apdu.sendBytesLong(buf, inputStart, retValues[0]);
  }

  // This method is called to handle dispatch commands during unsecure state.
  // These are all related to establishing secure channel so forward them to secure channel.
  private short dispatchUnsecure(byte[] buf, short index, short len, FiraAppletContext context,
      short[] retValues) {
    if (context.getSecureChannel() == null) {
      context.setSecureChannel(
          FiraSecureChannel.create(FiraSecureChannel.FIRA_SC_PROTOCOL, context));
    }
    print(buf , index, len);
    len = FiraSCHandler.handleProtocolObject(buf, index, len, context);
    short eventDataLen = FiraSCHandler.getNotification(buf, (short) (index + len), context, retValues);
    short eventId = retValues[0];
    return pushDispatchResponse(buf, index, len,
        FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER,
        (byte) eventId, buf, (short) (index + len), eventDataLen, retValues);
  }

  //TODO FiraApplet Specs are not clear enough in case of error. The assumption is that if the error occurs
  //  during processing of CAPDU that will be returned as response to too peer device i.e. initiator
  //  device. On receiving this error initiator FiraApplet Applet  will return back transaction error
  //  to the Fira FW.
  private short pushDispatchResponse(byte[] buf, short index, short len, short status, byte eventId,
      byte[] eventData, short eventIndex, short eventDataLen, short[] retValues) {
    short dataStart = index;
    index = (short) (index + eventDataLen + len + 32); // 32 bytes as extra buffer to account for the tags and lengths.
    short end = index;
    if(eventDataLen > 0) {
      index = pushNotification(buf, index, eventDataLen, eventId, eventData, eventIndex, eventDataLen);
    }
    if (len > 0) {
      index -= len;
      Util.arrayCopyNonAtomic(buf, dataStart, buf, index, len);
      index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_DATA, len);
    }
    if (status == FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER &&
        len == 0) {
      // Exception occurred on responding device
      Util.setShort(buf, index, ISO7816.SW_UNKNOWN);
      index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_DATA, (short)2);
    } //else Either exception occurred on initiator device or there is no error.
    //Add Status Tag
    index = FiraUtil.pushByte(buf, index, (byte)status);
    index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_STATUS,
        (short) 1);
    index = FiraUtil.pushBerTagAndLength(buf, index,
        FiraSpecs.TAG_PROPRIETARY_RESP_TEMPLATE, (short) (end - index));
    retValues[0] = (short) (end - index);
    return index;
  }

  private short pushNotification(byte[] buf, short index, short len,
      byte eventId, byte[] eventData, short eventIndex, short eventDataLen) {
    short end = index;
    // If there is event to be added
    if (eventId != FiraAppletContext.EVENT_INVALID) {
      //If Notification event data
      if (eventDataLen > 0) {
        index = FiraUtil.pushBERTlv(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_NOTIFICATION_DATA,
            eventData, eventIndex, eventDataLen);
      }
      // Add Event Identifier
      if (eventId == FiraAppletContext.EVENT_OID) {
        eventId = FiraSpecs.VAL_PROPRIETARY_RESP_NOTIFICATION_ID_OID;
      } else if (eventId == FiraAppletContext.EVENT_RDS) {
        eventId = FiraSpecs.VAL_PROPRIETARY_RESP_NOTIFICATION_ID_RDS;
      } else {
        eventId = FiraSpecs.VAL_PROPRIETARY_RESP_NOTIFICATION_ID_NONE;
      }
      index = FiraUtil.pushByte(buf, index, eventId);
      index = FiraUtil.pushBerTagAndLength(buf, index,
          FiraSpecs.TAG_PROPRIETARY_RESP_NOTIFICATION_ID, (short) 1);
      // Added format - mandatory
      index = FiraUtil.pushByte(buf, index, FiraSpecs.VAL_PROPRIETARY_RESP_NOTIFICATION_FMT);
      index = FiraUtil.pushBerTagAndLength(buf, index,
          FiraSpecs.TAG_PROPRIETARY_RESP_NOTIFICATION_FMT, (short) 1);
      // Add the notification tag
      index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_NOTIFICATION,
          (short) (end - index));
    }
    return index;
  }

  // The command supports is mainly TUNNEL command. On initiator side it will
  // originate the command in processTunnel. So on initiator this method is called to handle
  // the response of tunnel i.e. TUNNEL_ACTIVE state. On the responder side it should be idle state.
  // TODO Assumption is that transaction error will be returned if the status returned by
  //  responder is not 0x9000.
  //  Also, there is no terminate session notification in FIRA Specs although sequence chart shows
  //  it. We added custom notification for this as a placeholder.
  private short dispatchSecure(byte[] buf, short index, short len,
      FiraAppletContext context, short[] retValues) {
    print(buf , index, len);
    short eventId = FiraAppletContext.EVENT_INVALID;
    short eventDataLen = 0;
    short opState = context.getOpState();
    short status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_TRANS_SUCCESS;
    try {
      switch (opState) {
        case FiraAppletContext.OP_TUNNEL_ACTIVE:
          // Just send the response back to the framework.
          // TODO confirm that we do not need to validate the response.
          if (Util.getShort(buf, index) != (short) 0x9000) {
            status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_TRANS_ERROR;
          }
          if(context.isTerminateSession()){
            terminateSession(context);
          }
          context.clearOperationState();
          break;
        case FiraAppletContext.OP_IDLE:
          // Handle the command that is tunneled to responder.
          len = handleTunneledCommand(buf, index, len, context, retValues);
          index = retValues[0];
          status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER;
          break;
        default:
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
          break;
      }
      eventDataLen = FiraSCHandler.getNotification(buf, (short) (index + len), context, retValues);
      eventId = retValues[0];
    } catch (ISOException exception) {
      if (context.getOpState() == FiraAppletContext.OP_TUNNEL_ACTIVE) {
        len = 0;
        status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_TRANS_ERROR;
      } else {
        Util.setShort(buf, index, exception.getReason());
        len = 2;
      }
      context.setOpState(FiraAppletContext.OP_IDLE);
    }
    return pushDispatchResponse(buf, index, len, status,
        (byte) eventId, buf, (short) (index + len), eventDataLen, retValues);
  }

  //TODO this command is not extended APDU. This is going against the FiraApplet Specs's own guideline.
  //  So, we assume that Lc will be present - three bytes long with 0.
  private void processGetDataCmd(APDU apdu, FiraAppletContext context) {
    // local secure instruction
    assertLocalUnSecure(context);
    byte[] buf = apdu.getBuffer();
    // Only two tags can be read using this command.
    short tag = Util.getShort(buf, ISO7816.OFFSET_P1);
    if (tag != FiraSpecs.TAG_PA_LIST && tag != FiraSpecs.TAG_FIRA_SC_ADF_CA_PUB_CERT) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Receive all
    apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    if (buf.length < IMPL_APDU_BUFFER_MAX_SIZE) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Get the memory buffer from Applet data
    byte[] mem = FiraRepository.getAppletData(tag, retValues);
    // Read tag
    short end = FiraUtil.getTag(tag, mem, retValues[1], retValues[2], false, retValues);
    if (end == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    }
    inputLen = (short) (end - retValues[0]);
    // copy that in to the apdu buffer
    Util.arrayCopyNonAtomic(mem, retValues[0], buf, inputStart, inputLen);
    print(buf, inputStart, inputLen);
    apdu.setOutgoing();
    apdu.setOutgoingLength(inputLen);
    apdu.sendBytesLong(buf, inputStart, inputLen);
  }

  private short processPutDataCmd(byte[] buf, short index, short len, FiraAppletContext context) {
    // Put data can have only one data object tag.
    FiraUtil.getNextTag(buf, index, len, true, retValues);
    switch (retValues[1]) {
      case FiraSpecs.TAG_TERMINATE_SESSION:
        terminateSession(context);
        break;
      case FiraSpecs.TAG_UWB_SESSION_DATA:
        putSessionData(buf, index, len, context);
        break;
      case FiraSpecs.TAG_UWB_CONTROLEE_INFO:
        putControleeInfo(buf, index, len, context);
        break;
      case FiraSpecs.TAG_SERVICE_DATA:
        putServiceData(buf, index, len, context);
        break;
      case FiraSpecs.TAG_CMD_ROUTE_INFO:
        getPutCmdRouteInfo(buf, index, len, context);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        break;
    }
    Util.setShort(buf, index, (short) 0x9000);
    return (short) 2;
  }
  //TODO it is not clear in the specs that where in ADF the service applet AID is stored. We
  // assume it will be in ADF as custom tag. Note: the AID is stored in FW Service Init but
  // mot in ADF. It is just mentioned that this is stored in ADF during the provisioning time.
  // Also, it is not clear in Figure 38 whether FIRA FW in FIRA Device will send the SELECT
  // to service applet in FIRA Device1? or is it something else? We assume that FIRA FW will
  // send this because it stores it in its init parameters.
  private short getPutCmdRouteInfo(byte[] buf, short index, short len, FiraAppletContext context) {
    // Read the tag CMD ROUTING INFO and validate it
    short tagEnd = FiraUtil.getNextTag(buf, index, len, true, retValues);
    short tagStart = retValues[3];
    short tagLen = retValues[2];
    assertOrderedStructure(buf, tagStart, tagLen, FiraSpecs.STRUCT_CMD_ROUTE_INFO,true, buf,
        (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    //read the target and check whether it is HOST or Service Applet.
    // Read the target
    tagEnd = FiraUtil.getNextTag(buf,tagStart, tagLen,false,retValues);
    short routeTarget = retValues[3];
    if(routeTarget != FiraSpecs.VAL_SERVICE_APPLET){
      // TODO Currently, routing to application is not supported, but can be easily supported in future
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }else {
      len = routeToServiceApplet(buf, tagStart, tagLen, buf, (short)(tagStart + tagLen) , context);
    }
    return len;
  }

  private short routeToServiceApplet(byte[] buf, short tagStart, short tagLen,
      byte[] outBuf, short outIndex,  FiraAppletContext context) {
    // Check whether there is data amd it is not zero length
    FiraUtil.getTag(FiraSpecs.TAG_CMD_ROUTING_DATA, buf, tagStart,tagLen,false,retValues);
    if(retValues[2] < 6){ // At least two tags with at least one byte of value must be present
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    short cmdIndex = retValues[3];
    short cmdLen = retValues[2];
    byte ref = context.getAppletRef();
    if(ref != FiraSpecs.INVALID_VALUE) {
      // First validate that CMD ROUTING INFO in the ADF defined service applet id tag and
      // that matches the registered list of Service Applets
      byte[] mem = FiraRepository.getSlotData(FiraSpecs.TAG_CMD_ROUTE_INFO, (byte) context.getSlot(),
          retValues);
      short memIndex = retValues[1];
      short memLen = retValues[2];
      // Now search the APPLET ID Tag in CMD ROUTING INFO in ADF
      short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_CMD_ROUTE_INFO, mem, memIndex, memLen, true,
          retValues);
      if (tagEnd == FiraSpecs.INVALID_VALUE) {
        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
      }
      tagStart = retValues[3];
      tagLen = retValues[2];
      tagEnd = FiraUtil.getTag(FiraSpecs.TAG_SERVICE_APPLET_ID, mem, tagStart, tagLen, false,
          retValues);
      if (tagEnd == FiraSpecs.INVALID_VALUE) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      tagStart = retValues[3];
      tagLen = retValues[2];
      // So the APPLET ID exists so check whether it is already registered.
      ref = getServiceApplet(mem, tagStart, (byte) tagLen);
      if (ref == FiraSpecs.INVALID_VALUE || serviceApplet[ref].isReserved()) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      // Get the OID
      mem = FiraRepository.getSlotData(FiraSpecs.TAG_OID, (byte) context.getSlot(), retValues);
      FiraUtil.getTag(FiraSpecs.TAG_OID, mem, retValues[1], retValues[2], true, retValues);
      // This is safe i.e. mem is passed in directly, because this will be passed to shareable
      // interface this will copy the memory.
      serviceApplet[ref].init(mem, retValues[3], retValues[2]);
      context.setAppletRef(ref);
    }
    // Applet is plugged in and so dispatch the command.
    return serviceApplet[ref].dispatch(buf, cmdIndex, cmdLen, outBuf, outIndex);
  }

  private void putControleeInfo(byte[] buf, short index, short len, FiraAppletContext context) {
    short tag = FiraUtil.getNextTag(buf, index, len, true, retValues);
    tag = FiraUtil.getTag(FiraSpecs.TAG_UWB_CAPABILITY, buf, retValues[3], retValues[2],
        false, retValues);
    // UWB Capability can only be set in root context.
    if (tag != FiraSpecs.INVALID_VALUE && !context.isRoot()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    tag = FiraUtil.getTag(FiraSpecs.TAG_UWB_REGULATORY_INFO, buf, retValues[3], retValues[2], false,
        retValues);
    // UWB Regular info can only be set in root context.
    if (tag != FiraSpecs.INVALID_VALUE && !context.isRoot()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Everything else can be written in a secure context which is checked beforehand.
    if (context.isRoot()) {
      FiraRepository.putSharedDataObject(buf, index, len);
    } else {
      FiraRepository.putData(FiraSpecs.TAG_UWB_CONTROLEE_INFO, buf, index, len,
          (byte) context.getSlot());
    }
  }

  // TODO In case of session data. we assume that config data tag will be present. If put data comes
  //  without config data tag then it will be considered as an error. Also, we assume that
  //  put session data will always terminate the local session - both at controller and controlee
  //  ends.
  private void putSessionData(byte[] buf, short index, short len, FiraAppletContext context) {
    // Only possible in remote secure state
    assertRemoteUnSecure(context);
    // Add the session data to repository
    FiraRepository.putData(FiraSpecs.TAG_UWB_SESSION_DATA, buf, index, len, (byte) context.getSlot());
    // If the config available tag is present then generate RDS and send that to SUS
    short configAvailable = FiraUtil.getTag(FiraSpecs.TAG_UWB_CONFIG_AVAILABLE, buf, index, len,
        true, retValues);
    //TODO Assumption is as follows: If config available is present then generate rds. If config
    // available is not present but extended option is present and it is not default generation then
    // generate rds and then terminate. Note: if extended option is present and default generation
    // is present then session will be terminated after session is established.
    short scratch = (short) (index + len);
    if (configAvailable != FiraSpecs.INVALID_VALUE ||
        (context.isAutoTerminate() && !context.isDefaultKeyGeneration())) {
      generateAndSendRDS(buf, index, len, buf, scratch, context);
    }
    // Terminate the session if required.
    if (context.isAutoTerminate()) {
      terminateSession(context);
    }
  }

  // Send the RDS to Sus Applet
  private short sendRDS(byte[] buf, short index, short len) {
    return susApplet.createRangingDataSet(buf,index,len,null,(short)0);
  }

  //TODO this is not required in the FIRAApplet so it is commented for now and still kept in the code
  // as placeholder for future reference.
  /*
  private short deleteRDS(byte[] buf, short index, short len){
    return susApplet.deleteRangingDataSet(buf, index, len, null, (short)0);
  }
   */

  private void generateAndSendRDS(byte[] buf, short index, short len,
      byte[] scratchPad, short start, FiraAppletContext context) {
    FiraSCHandler.generateRDS(buf, index, len, context);
    Util.arrayCopyNonAtomic(scratchPad, start, buf, index, len);
    sendRDS(buf, start, len);
  }

  private void putServiceData(byte[] buf, short index, short len, FiraAppletContext context) {
  }

  //TODO assumption is that if there is any other asynchronous operation on going then return error
  private short handleTunneledCommand(byte[] buf, short index, short len,
      FiraAppletContext context, short[] retValues) {
    short ins = buf[(short) (index + ISO7816.OFFSET_INS)];
    // TODO Only extended apdu are supported
    if (buf[(short) (index + ISO7816.OFFSET_LC)] != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    len = Util.getShort(buf, (short) (index + ISO7816.OFFSET_LC + (short)1));
    index += ISO7816.OFFSET_EXT_CDATA;
    switch (ins) {
      case FiraSpecs.INS_PUT_DATA:
        assertOrderedStructure(buf, index, len, FiraSpecs.DATA_REMOTE_PUT_DATA, true, buf,
            (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
        len = processPutDataCmd(buf, index, len, context);
        break;
      case FiraSpecs.INS_GET_DATA:
        short tagEnd = FiraUtil.getNextTag(buf, index, len, true, retValues);
        if (tagEnd == FiraSpecs.INVALID_VALUE || retValues[1] != FiraSpecs.TAG_GET_CMD) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        index = retValues[3];
        len = retValues[2];
        len = processRemoteGetDataCmd(buf, index, len, context, retValues);
        index = retValues[0];
        break;
      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        break;
    }
    retValues[0] = index;
    return len;
  }

  private short processRemoteGetDataCmd(byte[] buf, short index, short len, FiraAppletContext context,
      short[] retValues) {
    short dataObject = FiraUtil.getNextTag(buf, index, len, true, retValues);
    short tag = retValues[1];
    short tagLen = retValues[2];
    short tagVal = retValues[3];

    switch (retValues[1]) {
      case FiraSpecs.TAG_UWB_CONTROLEE_INFO:
        len = handleGetControleeInfo(buf, tagVal, tagLen, context, retValues);
        break;
      case FiraSpecs.TAG_UWB_SESSION_DATA:
        len = handleGetSessionData(buf, tagVal, tagLen, context, retValues);
        break;
      case FiraSpecs.TAG_SERVICE_DATA:
        len = handleGetServiceData(buf, tagVal, tagLen, context, retValues);
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        break;
    }
    return len;
  }

  // TODO assumption is that is the tag is not found then error will be returned. This is important
  //  because controlee info can have tags missing and that takes default value. So we do not return
  //  default values.
  private short handleGetControleeInfo(byte[] buf, short index, short len, FiraAppletContext context,
      short[] retValues) {
    short slot = context.getSlot();
    short end = (short)(index + FiraSpecs.IMPL_MAX_UWB_CONTROLEE_INFO_SIZE + len);
    // Slot must be selected.
    if (slot == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Get handle to slot specific adf
    byte[] adfMem = FiraRepository.getSlotData(FiraSpecs.TAG_UWB_CONTROLEE_INFO, (byte) slot,
        retValues);
    short adfStart = retValues[1];
    short adfLen = retValues[2];
    print(adfMem, adfStart, adfLen);
    // Get handle to shared data
    byte[] sharedMem = FiraRepository.getSharedAdfData(FiraSpecs.TAG_UWB_CONTROLEE_INFO, retValues);
    short sharedLen = retValues[2];
    short sharedStart = retValues[1];
    print(sharedMem, sharedStart, sharedLen);
    // Read the tag
    short tagEnd = FiraUtil.getNextTag(buf, index, len, false, retValues);
    short tag1 = retValues[1];
    // Read the tags - there can be max 3 levels of tags in case of controlee info.
    if (tagEnd != FiraSpecs.INVALID_VALUE) {
      tagEnd = FiraUtil.getNextTag(buf, retValues[3], retValues[2], false, retValues);
      if (tagEnd != FiraSpecs.INVALID_VALUE && tagEnd != (short) (index + len)) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }
    tagEnd = FiraUtil.getTag(FiraSpecs.TAG_UWB_CONTROLEE_INFO, sharedMem, sharedStart, sharedLen,
        true, retValues);
    if (tagEnd != FiraSpecs.INVALID_VALUE) {
      sharedStart = retValues[3];
      sharedLen = retValues[2];
    }
    print(sharedMem, sharedStart, sharedLen);
    tagEnd = FiraUtil.getTag(FiraSpecs.TAG_UWB_CONTROLEE_INFO, adfMem, adfStart, adfLen, true,
        retValues);
    if (tagEnd != FiraSpecs.INVALID_VALUE) {
      adfStart = retValues[3];
      adfLen = retValues[2];
    }
    print(adfMem, adfStart, adfLen);
    // If entire controlee info needs to be returned
    if (tag1 == 0) {
      index = end;
      index = pushAdfTag(buf, index, sharedMem, sharedStart, sharedLen,
          FiraSpecs.TAG_UWB_REGULATORY_INFO);
      index = pushAdfTag(buf, index, adfMem, adfStart, adfLen,
          FiraSpecs.TAG_UWB_SECURE_RANGING_INFO);
      index = pushAdfTag(buf, index, adfMem, adfStart, adfLen,
          FiraSpecs.TAG_UWB_STATIC_RANGING_INFO);
      index = pushAdfTag(buf, index, adfMem, adfStart, adfLen,
          FiraSpecs.TAG_UWB_CONTROLEE_PREF);
      index = pushAdfTag(buf, index, sharedMem, sharedStart, sharedLen,
          FiraSpecs.TAG_UWB_CAPABILITY);
      index = pushAdfTag(buf, index, adfMem, adfStart, adfLen,
          FiraSpecs.TAG_UWB_CONTROLEE_INFO_VERSION);
    } else {
      // If the capability or regulatory info needs to be returned
      if (tag1 == FiraSpecs.TAG_UWB_REGULATORY_INFO || tag1 == FiraSpecs.TAG_UWB_CAPABILITY) {
        index = FiraUtil.push(buf, index, len, sharedMem, sharedStart, sharedLen, retValues,
            end);
      } else {
        // If another info from controlee info needs to be returned
        index = FiraUtil.push(buf, index, len, adfMem, adfStart, adfLen, retValues, end);
      }
    }
    index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_UWB_CONTROLEE_INFO,
        (short) (end - index));
    retValues[0] = index;
    return (short) (end - index);
  }

  private short pushAdfTag(byte[] buf, short index, byte[] mem, short start, short len, short tag) {
    // Get the data from adf
    short dataEnd = FiraUtil.getTag(tag, mem, start, len, true, retValues);
    // If it is not present then just return current index
    if (dataEnd == FiraSpecs.INVALID_VALUE) {
      return index;
    }
    // Else push the data from adf in the buf and return the new index
    return FiraUtil.pushBERTlv(buf, index, tag, mem, retValues[0], retValues[2]);
  }

  private short handleGetSessionData(byte[] buf, short index, short len, FiraAppletContext context,
      short[] retValues) {
    short slot = context.getSlot();
    short end = (short)(index + FiraSpecs.IMPL_MAX_UWB_SESSION_DATA_SIZE + len);
    // Slot must be selected.
    if (slot == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Get handle to slot specific adf
    byte[] adfMem = FiraRepository.getSlotData(FiraSpecs.TAG_UWB_SESSION_DATA, (byte) slot,
        retValues);
    short adfStart = retValues[1];
    short adfLen = retValues[2];
    print(adfMem, adfStart, adfLen);
    return FiraUtil.push(buf,index,len,adfMem, adfStart, adfLen, retValues,end);
  }

  private short handleGetServiceData(byte[] buf, short index, short len, FiraAppletContext context,
      short[] retValues) {
    short slot = context.getSlot();
    short end = (short)(index + FiraSpecs.IMPL_MAX_SERVICE_DATA_SIZE + len);
    // Slot must be selected.
    if (slot == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Get handle to slot specific adf
    byte[] adfMem = FiraRepository.getSlotData(FiraSpecs.TAG_SERVICE_DATA, (byte) slot,
        retValues);
    short adfStart = retValues[1];
    short adfLen = retValues[2];
    print(adfMem, adfStart, adfLen);
    return FiraUtil.push(buf,index,len,adfMem, adfStart, adfLen, retValues,end);
  }

  private void processImportADFCmd(APDU apdu, FiraAppletContext context) {
    // local secure instruction
    assertLocalSecure(context);
    byte[] buf = apdu.getBuffer();
    // P1 = 0 or 1, P2 = 0
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Receive all
    short len = apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    // Unwrap and decode
    unwrap(apdu, inputLen, context);
    assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_IMPORT_ADF_CMD,
        true, buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    // Add Applet specific OID
//    Util.arrayCopyNonAtomic(APPLET_OID, (short) 0, buf, (short) (inputStart + inputLen),
//        (short) APPLET_OID.length);
//    inputLen += (short) APPLET_OID.length;
    byte[] outBuf = buf;
    short outStart = (short) (inputStart + inputLen + 16); // 16 bytes extra
    // Check if there is enough space in the apdu buf to hold encrypted output and then encrypt
    // using  AES block cipher with padding.
    // Padding ,ay add upto one block of padding bytes (16 bytes)
    if ((short) (buf.length - outStart) < inputLen) {
      if (isDataCacheFree() && (short) (dataCache.length) >= (short) (inputLen + 16)) {
        outBuf = dataCache;
      } else { // else return error
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
    }
    inputLen = encryptAdf(buf, inputStart, outBuf, outStart, inputLen);
    // Wrap
    wrap(apdu, inputLen, context);
    // Send response
    apdu.setOutgoing();
    apdu.setOutgoingLength(inputLen);
    apdu.sendBytesLong(buf, inputStart, inputLen);
  }

  private void processSwapADFCmd(APDU apdu, FiraAppletContext context) {
    // local unsecure instruction
    assertLocalUnSecure(context);
    byte[] buf = apdu.getBuffer();
    // P1 = 0 or 1, P2 = 0
    if ((buf[ISO7816.OFFSET_P1] != FiraSpecs.INS_P1_SWAP_ADF_OP_ACQUIRE &&
        buf[ISO7816.OFFSET_P1] != FiraSpecs.INS_P1_SWAP_ADF_OP_RELEASE) ||
        buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Receive all
    short len = apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    byte slot;
    // Unwrap and decode
    unwrap(apdu, inputLen, context);
    //Acquire
    if (buf[ISO7816.OFFSET_P1] == FiraSpecs.INS_P1_SWAP_ADF_OP_ACQUIRE) {
      //TODO clear slot - just for testing
      context.clearSlot();
      // Check the slot
      if (context.getSlot() != FiraSpecs.INVALID_VALUE) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      // reserve the slot
      slot = (byte) FiraRepository.reserveDynamicSlot();
      if (slot == FiraSpecs.INVALID_VALUE) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      // Guard the slot
      try {
        assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_SWAP_ADF_ACQUIRE_CMD,
            true, buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
        //Read secure blob - Static STS is not supported
        short inputEnd = FiraUtil.getNextTag(buf, inputStart, inputLen, true, retValues);
        short secureBlobStart = retValues[3];
        short secureBlobLen = (short) (inputEnd - secureBlobStart);
        // Use data cache if it is free and the apdu buffer is not having enough space
        if (secureBlobLen < (short) (buf.length - inputLen)) {
          secureBlobLen = decryptAdf(buf, secureBlobStart, buf, inputEnd, secureBlobLen);
        } else if (!flags[DATA_CACHE_IN_USE] && secureBlobLen < dataCache.length) {
          secureBlobLen = decryptAdf(buf, secureBlobStart, dataCache, (short) 0, secureBlobLen);
          resetDataCache();
        } else {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Swap Adf is also like select adf TODO is this correct understanding?
        context.setSlot(slot);
        // Add the tags from the adf in secure blob
        FiraRepository.addMultipleDataObjects(buf, secureBlobStart, secureBlobLen, (byte) slot);
        // Return slot identifier
        // Set the slot
        buf[(short) 0] = slot;
        // Wrap
        wrap(apdu, (short) 1, context);
        // Send response
        apdu.setOutgoing();
        apdu.setOutgoingLength(inputLen);
        apdu.sendBytesLong(buf, (short) 0, (short) 1);
      } catch (Exception e) { // free the slot in case of the exception
        FiraRepository.freeSlot((byte) slot);
        // TODO: prashant
        // throw e;
      }
    } else { // Release the ADF
      // Get the slot number
      slot = buf[inputStart];
      // Error if the slot is already free
      if (FiraRepository.isSlotFree(slot)) {
        ISOException.throwIt(FiraSpecs.SLOT_NOT_FOUND);
      }
      // Free The slot
      FiraRepository.freeSlot((byte) slot);
      if (context.getSlot() != FiraSpecs.INVALID_VALUE) {
        context.clearSlot();
      }
    }
  }

  //Delete Adf
  //TODO it is not clear from specs, what to do if both adf is selected and oid is specified
  // In this case we give precedence to selected adf.
  // Also, current assumption is that a slot/adf is used mutually exclusively by the logical channels.
  private void processDeleteAdfCmd(APDU apdu, FiraAppletContext context) {
    //Assert context - cannot delete adf if the current context is in secure remote session
    if (context.isRemoteSecure()) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    byte[] buf = apdu.getBuffer();
    // P1 = 0 or 1, P2 = 0
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    byte slotId;
    // Receive all
    short len = apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    if (context.getSlot() != FiraSpecs.INVALID_VALUE) {
      slotId = (byte) context.getSlot();
      context.clearSlot();
      FiraRepository.freeSlot(slotId);
    } else if (inputLen != 0) { //OID must be given
      // validate input
      assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_DELETE_ADF_CMD,
          true, buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
      // get oid
      short oidEnd = FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true, retValues);
      short oidStart = retValues[0];
      short oidLen = (short) (oidEnd - oidStart);
      // free slot using oid
      slotId = FiraRepository.getSlot(buf, oidStart, oidLen);
      if (slotId == FiraSpecs.INVALID_VALUE) {
        ISOException.throwIt(FiraSpecs.OID_NOT_FOUND);
      } else {
        // Cannot delete ADF if it is being used i.e. it is selected by some channel
        if (FiraRepository.isSlotSelected(slotId)) {
          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        FiraRepository.freeSlot(slotId);
      }
      // no response required
    } else {// neither adf selected nor oid given
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private void processManageADFCmd(APDU apdu, FiraAppletContext context) {
    // local secure instruction
    assertLocalSecure(context);
    byte[] buf = apdu.getBuffer();
    // P1 = 0 or 1, P2 = 0
    if ((buf[ISO7816.OFFSET_P1] != FiraSpecs.INS_MANAGE_ADF_CONTINUE_P1 &&
        buf[ISO7816.OFFSET_P1] != FiraSpecs.INS_MANAGE_ADF_FINISH_P1) ||
        buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Receive all
    short len = apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    // Unwrap and decode
    unwrap(apdu, inputLen, context);
    //TODO just for testing
    //context.setSlot((byte) 0);
    //Handle the instruction
    short slot = context.getSlot();
    if (slot == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // If more Manage ADF APDU are expected
    byte[] cache = context.getDataCache();
    short dataStart = 2;
    short dataLen = 0;
    if (buf[ISO7816.OFFSET_P1] == FiraSpecs.INS_MANAGE_ADF_CONTINUE_P1) {
      // reserve the data cache.
      if (cache == null) {
        reserveDataCache();
        context.associateDataCache(dataCache);
      }
      // copy the data in the cache and return
      addToCache(buf, inputStart, inputLen);
    } else { // last manage adf and so commit the adf
      // if there is a cache then add the final adf to it
      if (cache != null) {
        addToCache(buf, inputStart, inputLen);
        dataLen = Util.getShort(cache, (short) 0);
        // commit the adf
      } else {
        cache = buf;
        dataStart = inputStart;
        dataLen = inputLen;
      }
      assertOrderedStructure(cache, dataStart, dataLen, FiraSpecs.DATA_MANAGE_ADF_CMD, true, buf,
          (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
      JCSystem.beginTransaction();
      FiraRepository.addMultipleDataObjects(cache, dataStart, dataLen, (byte) slot);
      JCSystem.commitTransaction();
    }
  }

  private void processCreateADFCmd(APDU apdu, FiraAppletContext context) {
    // Create Adf is a local secure instruction
    assertLocalSecure(context);
    // Context should have root slot to begin with.
    if (context.getSlot() != FiraRepository.ROOT_SLOT) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Reserve a static slot. Note: we do not set the slot in context because there can be multiple
    // create adfs for each static slot. Before manage adf there will be select adf.
    byte slot = (byte) FiraRepository.reserveStaticSlot();
    if (slot == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    byte[] buf = apdu.getBuffer();
    // CLA 0x84-0x87 or 0xE0-0xEF
    if (!(buf[ISO7816.OFFSET_CLA] >= (byte) 0x84 && buf[ISO7816.OFFSET_CLA] <= (byte) 0x87) &&
        !(buf[ISO7816.OFFSET_CLA] >= (byte) 0xE0 && buf[ISO7816.OFFSET_CLA] <= (byte) 0xEF)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // P1 = 0, P2 = 0
    if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Receive all the apdu data
    short len = apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    // Unwrap and decode
    unwrap(apdu, inputLen, context);
    assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_CREATE_ADF, true, buf,
        (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    // Check whether the OID already present in the repository
    retValues[4] = FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true, retValues);
    short existSlot = FiraRepository.getSlot(buf, retValues[0], (short) (retValues[4] - retValues[0]));
    if (existSlot != FiraSpecs.INVALID_VALUE) {
      FiraRepository.freeSlot(slot);
      ISOException.throwIt(FiraSpecs.OID_ALREADY_PRESENT);
    }
    // Replace ADF Provisioning tag with internal tag
    replaceTagNumber(FiraSpecs.TAG_ADF_PROVISIONING_CRED,
        FiraSpecs.TAG_STORED_ADF_PROVISIONING_CRED, buf, inputStart, inputLen);
    // Create the Adf.
    JCSystem.beginTransaction();
    FiraRepository.addMultipleDataObjects(buf, inputStart, inputLen, slot);
    JCSystem.commitTransaction();
  }

  private void replaceTagNumber(short target, short replacement, byte[] buf, short start, short len){
    short tagEnd = FiraUtil.getTag(target,buf,start,len,true,retValues);
    if(tagEnd != FiraSpecs.INVALID_VALUE){
      Util.setShort(buf, retValues[0],replacement);
    }
  }
  private short encryptAdf(byte[] buf, short inputStart, byte[] outBuf, short outStart,
      short inputLen) {
    //TODO Currently just placeholder ECB encryption - replace this with GCM in JCOP and using oneShot
    Cipher cipher = Cipher.getInstance((byte) Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    cipher.init(masterKey, Cipher.MODE_ENCRYPT);
    //PKCS7 padding
    byte paddingBytes = (byte) (inputLen % 16);
    if (paddingBytes == 0) {
      paddingBytes = (byte) 16;
    } else {
      paddingBytes = (byte) (16 - paddingBytes);
    }
    Util.arrayFillNonAtomic(buf, (short) (inputStart + inputLen), paddingBytes, paddingBytes);
    inputLen += paddingBytes;
    // encrypt
    inputLen = cipher.doFinal(buf, inputStart, inputLen, outBuf, outStart);
    // Copy back the data to input vector
    Util.arrayCopyNonAtomic(outBuf, outStart, buf, inputStart, inputLen);
    return inputLen;
  }

  private short decryptAdf(byte[] buf, short inputStart, byte[] outBuf, short outStart,
      short inputLen) {
    //TODO Currently just placeholder ECB encryption - replace this with GCM in JCOP and using oneShot
    Cipher cipher = Cipher.getInstance((byte) Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    cipher.init(masterKey, Cipher.MODE_DECRYPT);
    ;
    inputLen = cipher.doFinal(buf, inputStart, inputLen, outBuf, outStart);
    // remove padding
    inputLen -= outBuf[(short) (outStart + inputLen - 1)];
    // Copy back the data to input vector
    Util.arrayCopyNonAtomic(outBuf, outStart, buf, inputStart, inputLen);
    return inputLen;
  }

  private void unwrap(APDU apdu, short len, FiraAppletContext context) {
  }

  private void wrap(APDU apdu, short len, FiraAppletContext context) {
  }


  public boolean select(boolean b) {
    return true;
  }


  public void deselect(boolean b) {
    short i = 0;
  }


  public boolean select() {
    // TODO uncomment this
    return true;
  }


  public void deselect() {
    FiraAppletContext.getContext(APDU.getCLAChannel()).reset();
  }


  public void uninstall() {
    //Do nothing.
  }

  private short getType(short tagIndex) {
    if (tagIndex == FiraSpecs.NO_IDX) {
      return BYTES;
    } else if (tagIndex >= FiraSpecs.ENUM_IDX_OFFSET) {
      return ENUM;
    } else {
      return STRUCTURE;
    }
  }

  private short decode(byte[] buf, short index, short len, boolean ordered, byte count,
      byte tagIndex, byte[] scratchPadBuf, short scratchPadIndex) {
    if (ordered && (count != 0)) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);// This should never happen
    }
    // Get the expression
    short type = getType(tagIndex);
    //Handle the tag based on its expected type.
    switch (type) {
      case ENUM:
        assertEnumValue(buf, index, len, (short[]) (FiraSpecs.expressionTable(tagIndex)));
        index += len;
        break;
      case BYTES:
        index += len;
        break;
      case STRUCTURE:
        if (ordered) {
          assertOrderedStructure(buf, index, len,
              (short[]) (FiraSpecs.expressionTable(tagIndex)), false, scratchPadBuf,
              scratchPadIndex);
        } else {
          assertUnorderedStructure(buf, index, len,
              (short[]) (FiraSpecs.expressionTable(tagIndex)), count, false, scratchPadBuf,
              scratchPadIndex);
        }
        index += len;
        break;
      default:
        index = FiraSpecs.INVALID_VALUE;
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        break;
    }
    return index;
  }

  private void assertLength(short tagLength, short[] exp, short index) {
    short rule = exp[(short) (index + FiraSpecs.EXP_RULE_OFFSET)];
    boolean maxRule = (short) (rule & FiraSpecs.MAX) != 0;
    boolean eqRule = (short) (rule & FiraSpecs.LENGTH_RULE_MASK) == FiraSpecs.EQUAL;
    short len = (short) (rule & FiraSpecs.LENGTH_VAL_MASK);
    if ((maxRule && (tagLength > len)) || (eqRule && (tagLength != len))) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
  }

  private void assertEnumValue(byte[] buf, short index, short len, short[] exp) {
    short end = (short) exp.length;
    byte i = 0;
    // Currently, only 2 bytes or 1 byte values are specified in FiraApplet Specs.
    if (len > 2) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short value = (len == 2) ? Util.getShort(buf, index) : buf[index];
    while (i < end) {
      if (value == exp[i])
        return;
      i++;
    }
    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
  }

  private boolean getOrderAndCount(short[] exp, short expIndex, short[] retValues) {
    short rule = exp[(short) (expIndex + FiraSpecs.EXP_RULE_OFFSET)];
    boolean maxRule = (short) (rule & FiraSpecs.MAX) != 0;
    boolean ordered = (short) (rule & FiraSpecs.ORDER_RULE_MASK) == FiraSpecs.ORDERED;
    boolean countPresent = (short) (rule & FiraSpecs.COUNT) != 0;
    retValues[0] = 0;
    if (!ordered) {
      if (countPresent) {
        retValues[0] = (byte) (exp[(short) (expIndex + FiraSpecs.EXP_RULE_OFFSET)]
            & FiraSpecs.LENGTH_VAL_MASK);
      } else if (maxRule) {
        retValues[0] = 100;
      } else {
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      }
    }
    return ordered;
  }

  private void assertOrderedStructure(byte[] buf, short start, short len,
      short[] exp, boolean skip, byte[] scratchPadBuf, short scratchPad) {
    short index = start;
    short end = (short) (start + len);
    short expIndex = 0;
    while (index < end) {
      // Read the next tag - skip the 0s and FFs if desired.
      index = FiraUtil.getNextTag(buf, index, len, skip, retValues);
      short inTagStart = retValues[0];
      short inTag = retValues[1];
      short inLen = retValues[2];
      short valStart = retValues[3];
      expIndex = getMatchingExpression(inTag, exp, expIndex, true);
      if (expIndex == FiraSpecs.INVALID_VALUE) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      // Assert the length restriction
      assertLength(inLen, exp, expIndex);
      // Get order restriction of current expression
      boolean ordered = getOrderAndCount(exp, expIndex, retValues);
      if (decode(buf, valStart, inLen, ordered, (byte) retValues[0],
          (byte)exp[(short) (expIndex + FiraSpecs.EXP_INDEX_OFFSET)],
          scratchPadBuf, scratchPad) != index) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      if (len > 0) {
        len -= (short) (index - inTagStart);
      }
      expIndex += FiraSpecs.EXP_ROW_SIZE;
    }
    // Assert remaining mandatory tags
    assertMandatoryTags(exp, expIndex);
  }

  private void assertMandatoryTags(short[] exp, short expIndex) {
    while (expIndex < (short) exp.length) {
      if ((short) (exp[(short) (expIndex + FiraSpecs.EXP_RULE_OFFSET)] & FiraSpecs.MANDATORY)
          != 0) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      expIndex += FiraSpecs.EXP_ROW_SIZE;
    }
  }

  private short getMatchingExpression(short tag, short[] exp, short index, boolean ordered) {
    while (index < (short) exp.length) {
      if (exp[(short) (index + FiraSpecs.EXP_TAG_OFFSET)] == tag) {
        return index;
      }
      if (ordered && (
          (short) (exp[(short) (index + FiraSpecs.EXP_RULE_OFFSET)] & FiraSpecs.MANDATORY) != 0)) {
        break;
      }
      index += FiraSpecs.EXP_ROW_SIZE;
    }
    return FiraSpecs.INVALID_VALUE;
  }

  private void assertUnorderedStructure(byte[] buf, short start, short len, short[] exp, byte count,
      boolean skip, byte[] scratchPadBuf, short scratchPad) {
    short index = start;
    short end = (short) (start + len);
    // For un ordered set it may happen that count is less than all the elements in the expression
    // In this case if the len of the incoming message is less than expression than exit the loop
    // whenever either of them is done.
    while (index < end) {
      // Read the next tag - skip the 0s and FFs if desired.
      index = FiraUtil.getNextTag(buf, index, len, skip, retValues);
      short inTagStart = retValues[0];
      short inTag = retValues[1];
      short inLen = retValues[2];
      short valStart = retValues[3];
      // For an unordered structure, always compare expression list from the start
      short expIndex = getMatchingExpression(inTag, exp, (short) 0, false);
      if (expIndex == FiraSpecs.INVALID_VALUE) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
      // If the tag matches with expression
      // Assert the length restriction
      assertLength(inLen, exp, expIndex);
      // decrement the count and check
      count--;
      if (count < 0) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      // Unordered structure cannot have unordered tags - this is according to FiraApplet Specs
      // This check can be removed in future if required
      boolean ordered = getOrderAndCount(exp, expIndex, retValues);
      if (!ordered) {
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      }
      // Decode the matching tag
      if (decode(buf, valStart, inLen, true, (byte) 0,
          (byte)exp[(short) (expIndex + FiraSpecs.EXP_INDEX_OFFSET)],
          scratchPadBuf, scratchPad) != index) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      if (len > 0) {
        len -= (short) (index - inTagStart);
      }
    }
  }

  private void assertUnSecureChannels(APDU apdu) {
    byte[] buf = apdu.getBuffer();
    // CLA 0x80-0x83 or 0xC0-0xCF
    if (!(buf[ISO7816.OFFSET_CLA] >= (byte) 0x80 && buf[ISO7816.OFFSET_CLA] <= (byte) 0x83) &&
        !(buf[ISO7816.OFFSET_CLA] >= (byte) 0xC0 && buf[ISO7816.OFFSET_CLA] <= (byte) 0xCF)) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
  }

  //TODO how would the interoperability work if the proprietary command format and response is used.
  //  It is not clear SELECT ADF wih multiple OIDs will use which privacy key set kvn because there
  //  are multiple OIds, unless kvn is same in all the ADFs. The other thing which is not clear
  //  with respect to the privacy is how to interpret Extended Options on responder side
  //  i.e. if the privacy is available/enforced in controlee side but the kvn in the select adf
  //  command is not part of this adf - how does it work - perhaps responder will return an error?
  //  Also if there are no extended options and same thing happens then does responder return an
  //  error? If so what difference Extended Options make?
  //  Until the above questions are solved we assume that we will ignore extended options in case
  //  of privacy. Also, we shall assume that if privacy kvn is provided then it will be present in
  //  all the list of ADF.
  //  Now, on the initiator side it is not clear when if multiple OIDs are not provisioned and only one
  //  is provisioned, then would framework send multiple OIDs. In that case do we return an
  //  error or we just restrict the list to those OID that is provisioned. We assume that we do not
  //  validate the OID list and reject it if all of it is not supported on initiator side.
  //  So the approach for privacy is that if privacy kvn is present in select ADF then we must enable
  //  privacy. If privacy kvn is not present in select ADF then check extended options and if
  //  privacy is set to "enforced" then reject it. At initiator side if privacy is set to "enforced"
  //  and there is no privacy keyset in the ADF then that is an error condition. Finally at
  //  responder side privacy kvn or keyset kvn must be found in ADF. On initiator side first
  //  available key set of given type and usage will always be selected.

  private void processInitTransaction(APDU apdu, FiraAppletContext context) {
    assertLocalUnSecure(context);
    //TODO assumption is that is already remote secure state is present then init transaction cannot
    // be processed. First the current session must be terminated.
    assertRemoteUnSecure(context);
    byte[] buf = apdu.getBuffer();
    // P1 = 0, P2 = 0
    if (buf[ISO7816.OFFSET_P1] != FiraSpecs.INS_P1_INITIATE_TRANSACTION_UNICAST &&
        buf[ISO7816.OFFSET_P1] != FiraSpecs.INS_P1_INITIATE_TRANSACTION_MULTICAST) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // The ADF must already be selected
    if (context.getSlot() == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    //TODO Only unicast controller is currently supported multicast sessions are not supported
    // - more information required on this such as how is the UWB Session ID used to attach to
    // existing session? Does this mean that session data is same, etc.?
    if (buf[ISO7816.OFFSET_P1] == FiraSpecs.INS_P1_INITIATE_TRANSACTION_MULTICAST) {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    // Receive all the apdu data
    apdu.setIncomingAndReceive();
    short inputStart = apdu.getOffsetCdata();
    short inputLen = apdu.getIncomingLength();
    // Decode
    assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_INITIATE_TRANSACTION,
        true, buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    // validate the OIDs - there will be only one or only the first one will always be the
    // selected adf.
    //TODO actually there can be more then one OIDs but Fira FW will only send one for now.
    // This needs to be changed in future.
    short oidEnd = FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true, retValues);
    short oidStart = retValues[0];
    short oidLen = (short)(oidEnd - oidStart);
    context.setSecureChannel(FiraSecureChannel.create(FiraSecureChannel.FIRA_SC_PROTOCOL, context));
    // Initiate the flow which will create select command.
    // The framework has to route it to correct peer device
    inputLen = FiraSCHandler.initiate(FiraSpecs.FIRA_APPLET_AID, (short) 0,
        (short) FiraSpecs.FIRA_APPLET_AID.length, buf, inputStart, inputLen,
        buf, oidStart, oidLen, context);
    inputStart = pushDispatchResponse(buf, inputStart, inputLen,
        FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER, (byte) FiraAppletContext.EVENT_INVALID,
        null, FiraSpecs.INVALID_VALUE, (short) 0, retValues);
    inputLen = retValues[0];
    // Send response
    apdu.setOutgoing();
    apdu.setOutgoingLength(inputLen);
    apdu.sendBytesLong(buf, inputStart, inputLen);
  }


  // APDU select command wrapped in DISPATCH APDU to select the FIRAApplet in the peer device.
  private short pushSelectCommand(byte[] selBuf, short selIndex, short selLen,
      byte[] buf, short index) {
    short end = index;
    // select command
    index = FiraUtil.pushBERTlv(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_DATA, selBuf, selIndex,
        selLen);
    //Status value
    index = FiraUtil.pushByte(buf, index, (byte) FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER);
    // Status tag and length
    index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_STATUS,
        (short) 1);
    // Proprietary response template
    index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_TEMPLATE,
        (short) (end - index));
    return index;
  }


  public short wrap(byte[] buf, short index, short len, FiraAppletContext context) {
    //TODO change the following
    //return FiraSCHandler.wrap(buf, index, len, context);
    return len;
  }

  public short unwrap(byte[] buf, short index, short len, FiraAppletContext context) {
    //TODO change the following
    //return FiraSCHandler.unwrap(buf, index, len, context);
    return len;
  }

  //TODO The assumption is that if Framework wants to terminate all the sessions then it will call
  // terminate session on each logical channels with remote session.
  // Also, TERMINATE SESSION is not an acknowledged command. This means initiator of terminate session
  // will terminate the session once the dispatch response with success is received.
  public void terminateSession(FiraAppletContext context) {
    // If we are in root context then terminate nothing.
    if (context.isRoot() || context.getSlot() == FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Reset the channel.
    FiraSCHandler.terminate(context);
    // Release the channel
    context.setSecureChannel(null);
    // Reset the state.
    context.setRemoteSecureState(FiraAppletContext.REMOTE_UNSECURE);
    if(context.getAppletRef() != FiraSpecs.INVALID_VALUE &&
        serviceApplet[context.getAppletRef()].isReserved()){
      serviceApplet[context.getAppletRef()].cleanUp();
      context.setAppletRef(FiraSpecs.INVALID_VALUE);
    }
    //TODO uncomment the following for JCOP version
    // Release the references
    //JCSystem.requestObjectDeletion();
  }

  private void assertSecureChannels(APDU apdu) {
    byte[] buf = apdu.getBuffer();
    if (!(buf[ISO7816.OFFSET_CLA] >= (byte) 0x84 && buf[ISO7816.OFFSET_CLA] <= (byte) 0x87) &&
        !(buf[ISO7816.OFFSET_CLA] >= (byte) 0xE0 && buf[ISO7816.OFFSET_CLA] <= (byte) 0xEF)) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
  }

  //--------------------------------- Following methods can be replaced by Store Data Apdu
  private void processProcessPACredentials(APDU apdu, FiraAppletContext context) {
    assertLocalUnSecure(context); // Change this to secure if it is required
    assertUnSecureChannels(apdu);
    apdu.setIncomingAndReceive();
    byte[] buf = apdu.getBuffer();
    short inputStart = apdu.getOffsetCdata();
    short inputLength = apdu.getIncomingLength();
    switch (buf[ISO7816.OFFSET_P1]){
      case P1_ADD_PA_CRED:
        addPACredentials(buf, inputStart, inputLength, context);
        break;
      case P1_REMOVE_PA_CRED:
        removePACredentials(buf, inputStart, inputLength, context);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
    }
  }

  private void addPACredentials(byte[] buf, short inputStart, short inputLen, FiraAppletContext context) {
    assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_PA_RECORD, true,
        buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - IMPL_SCRATCH_PAD_MAX_SIZE));
    // Read the tag to add
    short valEnd = FiraUtil.getNextTag(buf,inputStart,inputLen, true,retValues);
    short valStart = retValues[0];
    byte[] mem = FiraRepository.getSharedAdfData(FiraSpecs.TAG_PA_RECORD, retValues);
    short memMaxLen = retValues[0];
    short memStart = retValues[1];
    short memLen = retValues[2];
    // search the records.
    short recordEnd = FiraUtil.search(FiraSpecs.TAG_PA_RECORD, FiraSpecs.TAG_PA_CRED_PA_ID,
        buf, valStart, (short) (valEnd - valStart), mem, memStart, memLen, retValues);
    // error if the record exists
    if (recordEnd != FiraSpecs.INVALID_VALUE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    // Add the PA Record tag - we will have at least 7 bytes in front.
    inputStart = FiraUtil.pushBERLength(buf,inputStart, inputLen);
    inputStart = FiraUtil.pushBERTag(buf, inputStart, FiraSpecs.TAG_PA_RECORD);
    // add the record
    FiraRepository.putSharedDataObject(buf, inputStart, inputLen);
  }

  private void processProcessSDCredentials(APDU apdu, FiraAppletContext context) {
    assertLocalUnSecure(context); // Change this to secure if it is required
    assertUnSecureChannels(apdu);
    apdu.setIncomingAndReceive();
    if (context.getSlot() != FiraSpecs.INVALID_VALUE &&
        context.getSlot() != FiraRepository.APPLET_SLOT) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    context.setSlot(FiraRepository.APPLET_SLOT);
    byte[] buf = apdu.getBuffer();
    short inputStart = apdu.getOffsetCdata();
    short inputLength = apdu.getIncomingLength();
    // TODO We just check presence of tags but we do not validate cert.
    short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_CERT, buf, inputStart, inputLength, true, retValues);
    if(tagEnd == FiraSpecs.INVALID_VALUE){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    tagEnd = FiraUtil.getTag(FiraSpecs.TAG_DEVICE_UID, buf, inputStart, inputLength, true, retValues);
    if(tagEnd == FiraSpecs.INVALID_VALUE){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    tagEnd = FiraUtil.getTag(FiraSpecs.TAG_APPLET_SECRET, buf, inputStart, inputLength, true, retValues);
    if(tagEnd == FiraSpecs.INVALID_VALUE){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    FiraRepository.putAppletDataObject(buf, inputStart, inputLength);
  }

  private void removePACredentials(byte[] buf, short inputStart, short inputLen, FiraAppletContext context) {
    // Get the PA Record file.
    byte[] mem = FiraRepository.getSharedAdfData(FiraSpecs.TAG_PA_RECORD, retValues);
    short memMaxLen = retValues[0];
    short memStart = retValues[1];
    short memLen = retValues[2];
    // search the records for given PA Identifier
    short recordEnd = FiraUtil.search(FiraSpecs.TAG_PA_RECORD, FiraSpecs.TAG_PA_CRED_PA_ID,
        buf, inputStart, inputLen, mem, memStart, memLen, retValues);
    // erase the record if it exists
    if (recordEnd != FiraSpecs.INVALID_VALUE) {
      FiraRepository.perform(FiraRepository.DELETE,mem, memStart, memLen, memMaxLen,
          retValues[0],retValues[2],null, (short)0, (short)0);
    }
  }

  private short search(short parentTag, short tag, byte val, byte[] mem, short index, short len, short[] retValues){
    short end = (short)(index + len); // end of the credentials.
    // Read the key sets one by one - index points to beginning of the key set and the end points to
    // end of all the key sets.
    while (index < end) {
      // read the key set
      short tagEnd = FiraUtil.getNextTag(mem, index, len, false, retValues);
      if(parentTag == FiraSpecs.INVALID_VALUE || parentTag == retValues[1]){
        short curParent = retValues[1];
        index = retValues[3];
        len = retValues[2];
        // If didn't find any remaining parent struct then error
        if (tagEnd == FiraSpecs.INVALID_VALUE) {
          break;
        }
        // else find the tag value in this set
        tagEnd = FiraUtil.getTag(tag, mem, index, len, false, retValues);
        // Compare the returned value with the given value
        if (tagEnd != FiraSpecs.INVALID_VALUE && val == retValues[3]) {
          retValues[0] = len;
          retValues[1] = curParent;
          return index;
        }
      }
      //else increment the index to next potential tag
      index += len;
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

