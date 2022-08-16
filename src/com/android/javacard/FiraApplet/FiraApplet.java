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
package com.android.javacard.FiraApplet;

import com.android.javacard.SecureChannels.FiraSecureChannel;
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

/* Note: In case we want to check orderliness of incoming data enable(comment) 'FiraInputValidation'
 *       and disable(uncomment) FiraNoInputValidation
 */
import static com.android.javacard.FiraApplet.FiraNoInputValidation.*;
//import static com.android.javacard.FiraApplet.FiraInputValidation.*;
import org.firaconsortium.sus.SecureUwbService;

public class FiraApplet extends Applet implements AppletEvent, MultiSelectable, ExtendedLength {

    final static short IMPL_APDU_BUFFER_MAX_SIZE = 5000;
    static final byte DATA_CACHE_HEADER_LEN = 2;

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

    private static byte[] mResetFlag;

    /**
     * Constructor.
     */
    public FiraApplet() {
        retValues = JCSystem.makeTransientShortArray((short) 5, JCSystem.CLEAR_ON_DESELECT);

        // Following memory is used mainly for store data and manage adf commands.
        // TODO determine whether we require clear on reset or clear on deselect.
        dataCache = JCSystem.makeTransientByteArray(
                (short) (FiraSpecs.IMPL_TRANSIENT_ADF_SIZE + FiraSpecs.IMPL_PERSISTENT_ADF_SIZE),
                JCSystem.CLEAR_ON_DESELECT);
        flags = JCSystem.makeTransientBooleanArray(NUM_OF_FLAGS, JCSystem.CLEAR_ON_DESELECT);
        flags[DATA_CACHE_IN_USE] = false;
        // Create Master Key used for Import ADF.
        // TODO make master key upgradeable.
        masterKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, false);
        randomNumber(dataCache, (short) 0, (short) 16);
        masterKey.setKey(dataCache, (short) 0);
        resetDataCache();
        FiraAppletContext.init();
        FiraRepository.init();

        mResetFlag = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        // set mResetFlag
        mResetFlag[0] = 0x01;
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
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FiraApplet().register();
        serviceApplet = new FiraServiceAppletHandler[FiraSpecs.IMPL_MAX_SERVICE_APPLETS_COUNT];
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
        // First two bytes is the length of the stored data.
        short dataLen = Util.getShort(dataCache, (short) 0);

        if ((short) (dataLen + len) > (short) dataCache.length) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        Util.arrayCopyNonAtomic(buf, start, dataCache, (short) (DATA_CACHE_HEADER_LEN + dataLen),
                len);
        Util.setShort(dataCache, (short) 0, (short) (dataLen + len));
    }

    private void randomNumber(byte[] buf, short index, short len) {
        // TODO change to RandomData.oneShot
        RandomData rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        rng.nextBytes(buf, index, len);
    }

    /**
     * Throw exception if the contest is not local and secure.
     */
    private void assertLocalSecure(FiraAppletContext context) {
        if (!context.isLocalSecure()) {
            ISOException.throwIt(FiraSpecs.COND_NOT_SATISFIED);
        }
    }

    /**
     * Throw exception if the contest is not remote and secure.
     */
    private void assertRemoteSecure(FiraAppletContext context) {
        if (!context.isRemoteSecure()) {
            ISOException.throwIt(FiraSpecs.COND_NOT_SATISFIED);
        }
    }

    /**
     * Throw exception if the contest is not remote and secure.
     */
    private void assertRemoteUnSecure(FiraAppletContext context) {
        if (context.isRemoteSecure()) {
            ISOException.throwIt(FiraSpecs.COND_NOT_SATISFIED);
        }
    }

    /**
     * Throw exception if the contest is not local and unsecure.
     */
    private void assertLocalUnSecure(FiraAppletContext context) {
        if (!context.isLocalUnSecure()) {
            ISOException.throwIt(FiraSpecs.COND_NOT_SATISFIED);
        }
    }

    public void process(APDU apdu) throws ISOException {
        // If this is an APDU to select this applet then just return
        if (apdu.isISOInterindustryCLA() && selectingApplet()) {
            return;
        }

        // The applet uses extended apdu as its heap memory for processing.
        byte[] buf = apdu.getBuffer();

        // if (buf[ISO7816.OFFSET_LC] != 0 || apdu.getBuffer().length <
        //      IMPL_APDU_BUFFER_MAX_SIZE) {
        //    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // }

        if (mResetFlag[0x00] != 0x01) {
            short cnt = FiraAppletContext.getChannelCnt();
            while ((--cnt) >= 0) {
                FiraAppletContext.getContext(cnt).reset();
            }
            mResetFlag[0] = 0x01;
        }

        // Applet is multi selectable, get the context of the logical channel used in
        // the selection.
        FiraAppletContext context = FiraAppletContext.getContext(APDU.getCLAChannel());

        // assert the secure state of the context
        assertSecureState(buf[ISO7816.OFFSET_INS], context);

        // assert P1, P2
        assertP1P2(buf[ISO7816.OFFSET_INS], buf[ISO7816.OFFSET_P1], buf[ISO7816.OFFSET_P2]);

        // Receive data
        apdu.setIncomingAndReceive();
        short index = apdu.getOffsetCdata();
        short len = apdu.getIncomingLength();

        // process the instruction.
        switch (buf[ISO7816.OFFSET_INS]) {
//    case FIRASpecs.INS_STORE_DATA:
        case FiraSpecs.INS_PROVISION_SD_CREDENTIALS:
            len = processProvisionSDCredentials(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_PROVISION_PA_CREDENTIALS:
            len = processProcessPACredentials(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_PROVISION_SERVICE_APPLET:
            len = processProvisionServiceApplet(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_CREATE_ADF:
            len = processCreateAdfCmd(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_SELECT_ADF:
            len = processSelectAdf(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_MANAGE_ADF:
            len = processManageADFCmd(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_DELETE_ADF:
            len = processDeleteAdfCmd(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_IMPORT_ADF:
            len = processImportADFCmd(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_SWAP_ADF:
            len = processSwapADFCmd(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_INITIATE_TRANSACTION:
            len = processInitTransaction(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_DISPATCH:
            len = processDispatchCmd(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_TUNNEL:
            len = processTunnelCmd(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_GET_DATA:
            len = processGetDataCmd(
                    (short) (buf[ISO7816.OFFSET_P1] << 8 | (buf[ISO7816.OFFSET_P2] & 0x00FF)), buf,
                    index, len, context, retValues);
            break;
        case FiraSpecs.INS_PUT_DATA:
            len = processPutDataCmd(buf, index, len, context, retValues);
            break;
        case FiraSpecs.INS_PERFORM_SECURITY_OPERATION:
        case FiraSpecs.INS_MUTUAL_AUTH:
            len = processScp11cCmd(buf, index, len, context, retValues);
            break;

        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            break;
        }
        index = retValues[0];

        if (len > 0) {
            // Send the response if any
            apdu.setOutgoing();
            apdu.setOutgoingLength(len);
            apdu.sendBytesLong(buf, index, len);
        }
    }

    private void assertP1P2(byte instruction, short p1, short p2) {
        boolean err = false;

        switch (instruction) {
        case FiraSpecs.INS_SWAP_ADF:
            err = p1 != FiraSpecs.INS_P1_SWAP_ADF_OP_ACQUIRE
                    && p1 != FiraSpecs.INS_P1_SWAP_ADF_OP_RELEASE || p2 != 0;
            break;
        case FiraSpecs.INS_PROVISION_SERVICE_APPLET:
            err = p1 != P1_ADD_SERVICE_APPLET && p1 != P1_REMOVE_SERVICE_APPLET || p2 != 0;
            break;
        case FiraSpecs.INS_INITIATE_TRANSACTION:
            err = p1 != FiraSpecs.INS_P1_INITIATE_TRANSACTION_MULTICAST
                    && p1 != FiraSpecs.INS_P1_INITIATE_TRANSACTION_UNICAST || p2 != 0;
            // Multicast not supported
            if (p1 == FiraSpecs.INS_P1_INITIATE_TRANSACTION_MULTICAST) {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            break;
        case FiraSpecs.INS_SELECT_ADF:
            err = p1 != 4 || p2 != 0;
            break;
        case FiraSpecs.INS_MANAGE_ADF:
            err = p1 != FiraSpecs.INS_MANAGE_ADF_CONTINUE_P1
                    && p1 != FiraSpecs.INS_MANAGE_ADF_FINISH_P1 || p2 != 0;
            break;
        case FiraSpecs.INS_GET_DATA:
            short p1p2 = (short) (p1 << 8 | (short) (p2 & 0x00FF));
            err = p1p2 != FiraSpecs.TAG_PA_LIST && p1p2 != FiraSpecs.TAG_APPLET_CERT_STORE
                    && p1p2 != FiraSpecs.TAG_STATIC_STS_SLOT_OID && p1p2 != 0x3FFF; // This is used
                                                                                    // for arbitrary
                                                                                    // GET Data
                                                                                    // command.
            break;
        case FiraSpecs.INS_PUT_DATA:
        case FiraSpecs.INS_CREATE_ADF:
        case FiraSpecs.INS_DELETE_ADF:
        case FiraSpecs.INS_IMPORT_ADF:
        case FiraSpecs.INS_DISPATCH:
        case FiraSpecs.INS_TUNNEL:
        case FiraSpecs.INS_PROVISION_SD_CREDENTIALS:
        case FiraSpecs.INS_PROVISION_PA_CREDENTIALS:
            err = p1 != 0 || p2 != 0;
            break;
        default:
            break;
        }
        if (err) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void assertSecureState(byte instruction, FiraAppletContext context) {
        switch (instruction) {
        case FiraSpecs.INS_SWAP_ADF:
        case FiraSpecs.INS_INITIATE_TRANSACTION:
        case FiraSpecs.INS_PROVISION_SD_CREDENTIALS:
        case FiraSpecs.INS_PROVISION_PA_CREDENTIALS:
        case FiraSpecs.INS_PROVISION_SERVICE_APPLET:
            assertRemoteUnSecure(context);
        case FiraSpecs.INS_PERFORM_SECURITY_OPERATION:
        case FiraSpecs.INS_MUTUAL_AUTH:
            assertLocalUnSecure(context);
            break;
        case FiraSpecs.INS_SELECT_ADF:
            assertRemoteUnSecure(context);
            break;
     // case FIRASpecs.INS_STORE_DATA:
        case FiraSpecs.INS_CREATE_ADF:
        case FiraSpecs.INS_MANAGE_ADF:
        case FiraSpecs.INS_DELETE_ADF:
        case FiraSpecs.INS_IMPORT_ADF:
            assertLocalSecure(context); // This ensures remote unsecure context
            break;
        case FiraSpecs.INS_TUNNEL:
            assertRemoteSecure(context); // Also means local unsecure
            break;
        case FiraSpecs.INS_DISPATCH: // DISPATCH is used both in remote unsecure and secure state.
            assertLocalUnSecure(context);
            break;
        case FiraSpecs.INS_PUT_DATA:
        case FiraSpecs.INS_GET_DATA:
            if (context.isRemoteUnSecure() && context.isLocalUnSecure()) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            break;
        }
    }

    private short processPutDataCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        // Either local or remotely secure instruction. if remotely secured then slot
        // should be
        // valid, and it should not be root slot. If locally secured then slot should be
        // valid and
        // not APPLET SLOT.
        short slot = context.getSlot();
        if ((context.isRemoteUnSecure() && context.isLocalUnSecure())
                || (context.isRemoteSecure() && (slot == FiraSpecs.INVALID_VALUE
                        || slot == FiraRepository.ROOT_SLOT || slot == FiraRepository.APPLET_SLOT))
                || (context.isLocalSecure() && slot == FiraRepository.APPLET_SLOT)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // If local secure then always use root slot if none selected.
        if (context.isLocalSecure() && context.getSlot() == FiraSpecs.INVALID_VALUE) {
            context.setRoot();
        }

        assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_LOCAL_PUT_DATA, true, buf,
                (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                retValues);
        processPutDataCmd(buf, inputStart, inputLen, context);
        // There is no response data.
        return 0;
    }

    public short processTunnelCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        // There should be no other active async operation.
        if (context.getOpState() != FiraAppletContext.OP_IDLE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // decode
        assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_TUNNEL, true, buf,
                (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                retValues);
        // Read the proprietary command template tag
        FiraUtil.getNextTag(buf, inputStart, inputLen, true, retValues);
        // read the child tag i.e. proprietary command data of the proprietary tag
        FiraUtil.getNextTag(buf, retValues[3], retValues[2], true, retValues);
        // Pass the value of the expected command
        inputStart = retValues[3];
        inputLen = retValues[2];

        // Tunneled instruction must be extended apdu
        if (buf[(short) (inputStart + ISO7816.OFFSET_LC)] != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short ins = buf[(short) (inputStart + ISO7816.OFFSET_INS)];
        // Tunnel can be used for PUT or GET data
        if (ins != FiraSpecs.INS_PUT_DATA && ins != FiraSpecs.INS_GET_DATA) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        short insLen = Util.getShort(buf, (short) (inputStart + ISO7816.OFFSET_LC + (short) 1));
        short insStart = (short) (inputStart + ISO7816.OFFSET_EXT_CDATA);

        // Note: if instruction gets or sets session data and or terminates session then
        // set the context
        // accordingly so that rds can be generated and/or session can be terminated at
        // the completion
        // of the command. This is done in dispatch response handling in dispatchSecure
        // method.
        if (ins == FiraSpecs.INS_PUT_DATA) {
            assertOrderedStructure(buf, insStart, insLen, FiraSpecs.DATA_REMOTE_PUT_DATA, true, buf,
                    (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                    retValues);

            short end = FiraUtil.getTag(FiraSpecs.TAG_UWB_SESSION_DATA, buf, insStart, insLen, true,
                    retValues);
            if (end != FiraSpecs.INVALID_VALUE) {
                context.enablePutSessionDataOpState();
                putSessionData(buf, retValues[0], (short) (end - retValues[0]), context);
            } else {
                end = FiraUtil.getTag(FiraSpecs.TAG_TERMINATE_SESSION, buf, insStart, insLen, true,
                        retValues);
                if (end != FiraSpecs.INVALID_VALUE) {
                    context.enableTerminateSessionOpState();
                }
            }
        } else { // Get Data
            FiraUtil.getNextTag(buf, insStart, insLen, true, retValues);
            if (retValues[1] != FiraSpecs.TAG_GET_CMD || retValues[2] <= 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            FiraUtil.getNextTag(buf, retValues[3], retValues[2], false, retValues);
            if (retValues[1] == FiraSpecs.TAG_UWB_SESSION_DATA) {
                context.enableGetSessionDataOpState();
            }
        }

        // wrap the entire instruction include apdu header - this is wrapping the
        // tunneled command.
        inputLen = wrap(buf, inputStart, inputLen, context);
        // create dispatch response
        inputStart = pushDispatchResponse(buf, inputStart, inputLen,
                FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER, FiraSpecs.INVALID_VALUE, null,
                FiraSpecs.INVALID_VALUE, (short) 0, retValues);
        inputLen = retValues[0];
        context.setOpState(FiraAppletContext.OP_TUNNEL_ACTIVE);
        retValues[0] = inputStart;
        return inputLen;
    }

    private short processDispatchCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        // decode
        assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_DISPATCH_CMD, true, buf,
                (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                retValues);
        // Read the proprietary command template tag
        FiraUtil.getNextTag(buf, inputStart, inputLen, true, retValues);
        // read the child tag i.e. proprietary command data of the proprietary tag
        FiraUtil.getNextTag(buf, retValues[3], retValues[2], true, retValues);
        // Pass the value to the expected command
        inputStart = retValues[3];
        inputLen = retValues[2];

        // The dispatch command can come during remote secure and unsecure states.
        switch (context.getRemoteChannelState()) {
        case FiraAppletContext.REMOTE_UNSECURE:
            inputStart = dispatchUnsecure(buf, inputStart, inputLen, context, retValues);
            if (FiraSCHandler.isSecure(context)) {
                context.setRemoteSecureState(FiraAppletContext.REMOTE_SECURE);
            }
            break;
        case FiraAppletContext.REMOTE_SECURE:
            // Multiple commands/responses can come in this state, and they will be
            // encrypted.
            inputLen = unwrap(buf, inputStart, inputLen, context);
            inputStart = dispatchSecure(buf, inputStart, inputLen, context, retValues);
            // wrapping is destination specific and done in dispatchSecure
            break;
        }
        inputLen = retValues[0];
        retValues[0] = inputStart;
        return inputLen;
    }

    // This method is called to handle dispatch commands during unsecure state.
    // These are all related to establishing secure channel so forward them to
    // secure channel.
    private short dispatchUnsecure(byte[] buf, short index, short len, FiraAppletContext context,
            short[] retValues) {
        short status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER;
        short eventDataLen = 0;
        short eventId = FiraSpecs.INVALID_VALUE;
        if (context.getSecureChannel() == null) {
            context.setSecureChannel(
                    FiraSecureChannel.create(FiraSecureChannel.FIRA_SC_PROTOCOL, context));
        }
        try {
            len = FiraSCHandler.handleProtocolObject(buf, index, len, context);
            eventDataLen = FiraSCHandler.getNotification(buf, (short) (index + len), context,
                    retValues);
            eventId = retValues[0];
        } catch (ISOException exp) {
            status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_TRANS_ERROR;
        }
        return pushDispatchResponse(buf, index, len, status, (byte) eventId, buf,
                (short) (index + len), eventDataLen, retValues);
    }

    private short pushDispatchResponse(byte[] buf, short index, short len, short status,
            byte eventId, byte[] eventData, short eventIndex, short eventDataLen,
            short[] retValues) {
        short dataStart = index;

        // 32 bytes as extra buffer to account for the tags and lengths.
        // Note: There can be upto 8 tags in a response and if we consider 4 bytes per
        // tag then
        // extra buffer required will be 32 bytes.
        index = (short) (index + eventDataLen + len + 32);
        short end = index;
        if (eventDataLen > 0) {
            index = pushNotification(buf, index, eventDataLen, eventId, eventData, eventIndex,
                    eventDataLen);
        }

        if (len > 0) {
            index -= len;
            Util.arrayCopyNonAtomic(buf, dataStart, buf, index, len);
            index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_DATA,
                    len);
        }

        if (status == FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER && len == 0) {
            // Exception occurred on responding device
            Util.setShort(buf, index, ISO7816.SW_UNKNOWN);
            index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_DATA,
                    (short) 2);
        } // else Either exception occurred on initiator device or there is no error.
          // Add Status Tag
        index = FiraUtil.pushByte(buf, index, (byte) status);
        index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_STATUS,
                (short) 1);
        index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_PROPRIETARY_RESP_TEMPLATE,
                (short) (end - index));
        retValues[0] = (short) (end - index);
        return index;
    }

    private short pushNotification(byte[] buf, short index, short len, byte eventId,
            byte[] eventData, short eventIndex, short eventDataLen) {
        short end = index;

        // If there is event to be added
        if (eventId != FiraAppletContext.EVENT_INVALID) {
            // If Notification event data
            if (eventDataLen > 0) {
                index = FiraUtil.pushBERTlv(buf, index,
                        FiraSpecs.TAG_PROPRIETARY_RESP_NOTIFICATION_DATA, eventData, eventIndex,
                        eventDataLen);
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
            index = FiraUtil.pushBerTagAndLength(buf, index,
                    FiraSpecs.TAG_PROPRIETARY_RESP_NOTIFICATION, (short) (end - index));
        }
        return index;
    }

    // The command supports is mainly TUNNEL command. Initiator side will originate
    // the command in
    // processTunnel. So on initiator this method is called to handle the response
    // of tunnel
    // i.e. TUNNEL_ACTIVE state. On the responder side it should be idle state.
    private short dispatchSecure(byte[] buf, short index, short len, FiraAppletContext context,
            short[] retValues) {
        short eventId = FiraAppletContext.EVENT_INVALID;
        short eventDataLen = 0, lastTag = 0;
        short opState = context.getOpState();
        short status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_TRANS_SUCCESS;

        try {
            switch (opState) {
            case FiraAppletContext.OP_TUNNEL_ACTIVE:
                // Just send the response back to the framework.
                if (Util.getShort(buf, (short) (index + len - 2)) != (short) 0x9000) {
                    status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_TRANS_ERROR;
                }

                if (context.isGetSessionData() || context.isPutSessionData()) {
                    generateAndSendRDS(buf, (short) (index + len), FiraSpecs.IMPL_MAX_RDS_DATA_SIZE,
                            context);
                }

                if (context.isTerminateSession()) {
                    terminateSession(context);
                }
                context.clearOperationState();
                break;
            case FiraAppletContext.OP_IDLE:
                // Handle the command that is tunneled to responder.
                len = handleTunneledCommand(buf, index, len, context, retValues);
                index = retValues[0];
                lastTag = retValues[1];
                status = FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER;
                Util.setShort(buf, (short) (index + len), (short) 0x9000);
                len += 2;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                break;
            }
            eventDataLen = FiraSCHandler.getNotification(buf, (short) (index + len), context,
                    retValues);
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

        // Wrap only if the destination is PEER - else the don't wrap.
        if (status == FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER) {
            // retValues[1] (lastTag) represent the tag value read inside
            // 'handleTunneledCommand'
            // if last tag is FiraSpecs.TAG_TERMINATE_SESSION then avoid any channel
            // operation
            if (lastTag != FiraSpecs.TAG_TERMINATE_SESSION)
                len = wrap(buf, index, len, context);
        }

        index = pushDispatchResponse(buf, index, len, status, (byte) eventId, buf,
                (short) (index + len), eventDataLen, retValues);
        len = retValues[0];
        return index;
    }

    private short processGetDataCmd(short p1p2, byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        if (context.getSlot() == FiraSpecs.INVALID_VALUE) {
            context.setRoot();
        }

        // If this is a standard command
        if ((inputLen == 0) && (p1p2 == FiraSpecs.TAG_PA_LIST
                || p1p2 == FiraSpecs.TAG_FIRA_SC_ADF_CA_PUB_CERT)) {
            assertLocalUnSecure(context);
            inputLen = handleStandardLocalGetCmd(p1p2, buf, inputStart);
        } else {// This is a custom FIRA FW specific command
            inputLen = handleCustomGetCmd(buf, inputStart, inputLen, context);
        }

        retValues[0] = inputStart;
        return inputLen;
    }

    private short handleCustomGetCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context) {
        // We only support Controlee Info, Session Data and Service Data.
        short tagEnd = FiraUtil.getNextTag(buf, inputStart, inputLen, true, retValues);

        if (tagEnd == FiraSpecs.INVALID_VALUE || retValues[1] != FiraSpecs.TAG_GET_CMD
                || retValues[2] == 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        tagEnd = FiraUtil.getNextTag(buf, retValues[3], retValues[2], true, retValues);
        if (tagEnd == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        short tag = retValues[1];
        // There is a special case in which the FIRA Fw can just request to get
        // Controlee Info from
        // Shared Adf part. In this case the slot will be the root slot.
        if (context.getSlot() == FiraRepository.ROOT_SLOT
                && retValues[1] == FiraSpecs.TAG_UWB_CONTROLEE_INFO && retValues[2] == 0) {
            byte[] mem = FiraRepository.getSharedAdfData(retValues[1], retValues);
            tagEnd = FiraUtil.getTag(tag, mem, retValues[1], retValues[2], true, retValues);
            if (tagEnd == FiraSpecs.INVALID_VALUE) {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
            }
            inputLen = (short) (tagEnd - retValues[0]);
            Util.arrayCopyNonAtomic(mem, retValues[0], buf, inputStart, inputLen);
        } else {
            inputLen = handleGetCommand(tag, buf, retValues[3], retValues[2], context, retValues);
            Util.arrayCopyNonAtomic(buf, retValues[0], buf, inputStart, inputLen);
        }

        return inputLen;
    }

    private short handleStandardLocalGetCmd(short tag, byte[] buf, short inputStart) {
        // Get the memory buffer from Applet data
        byte[] mem = FiraRepository.getAppletData(tag, retValues);

        // Read tag
        short end = FiraUtil.getTag(tag, mem, retValues[1], retValues[2], false, retValues);
        if (end == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        short inputLen = (short) (end - retValues[0]);
        // copy that in to the apdu buffer
        Util.arrayCopyNonAtomic(mem, retValues[0], buf, inputStart, inputLen);
        return inputLen;
    }

    private short processPutDataCmd(byte[] buf, short index, short len, FiraAppletContext context) {
        // Put data can have only one data object tag.
        short ret = 0;

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
            ret = getPutCmdRouteInfo(buf, index, len, context);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            break;
        }
        return ret;
    }

    private short getPutCmdRouteInfo(byte[] buf, short index, short len,
            FiraAppletContext context) {
        // Read the tag CMD ROUTING INFO and validate it
        FiraUtil.getNextTag(buf, index, len, true, retValues);
        short tagStart = retValues[3];
        short tagLen = retValues[2];

        assertOrderedStructure(buf, tagStart, tagLen, FiraSpecs.STRUCT_CMD_ROUTE_INFO, true, buf,
                (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                retValues);

        // read the target and check whether it is HOST or Service Applet.
        // Read the target
        FiraUtil.getNextTag(buf, tagStart, tagLen, false, retValues);
        short routeTarget = buf[retValues[3]];

        if (routeTarget != FiraSpecs.VAL_SERVICE_APPLET) {
            // TODO Currently, routing to application is not supported, but can be easily
            // supported in
            // future.
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        } else {
            len = routeToServiceApplet(buf, tagStart, tagLen, buf, (short) (tagStart + tagLen),
                    context);
            Util.arrayCopyNonAtomic(buf, (short) (tagStart + tagLen), buf, index, len);
        }
        return len;
    }

    private short routeToServiceApplet(byte[] buf, short tagStart, short tagLen, byte[] outBuf,
            short outIndex, FiraAppletContext context) {
        // Check whether there is data amd it is not zero length
        FiraUtil.getTag(FiraSpecs.TAG_CMD_ROUTING_DATA, buf, tagStart, tagLen, false, retValues);

        if (retValues[2] < 6) { // At least two tags with at least one byte of value must be present
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        short cmdIndex = retValues[3];
        short cmdLen = retValues[2];
        byte ref = context.getAppletRef();
        if (ref == FiraSpecs.INVALID_VALUE) {
            // First validate that CMD ROUTING INFO in the ADF defined service applet id tag
            // and
            // that matches the registered list of Service Applets
            byte[] mem = FiraRepository.getSlotSpecificAdfData(FiraSpecs.TAG_CMD_ROUTE_INFO,
                    (byte) context.getSlot(), retValues);
            short memIndex = retValues[1];
            short memLen = retValues[2];
            // Now search the APPLET ID Tag in CMD ROUTING INFO in ADF
            short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_CMD_ROUTE_INFO, mem, memIndex, memLen,
                    true, retValues);

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
            mem = FiraRepository.getSlotSpecificAdfData(FiraSpecs.TAG_OID, (byte) context.getSlot(),
                    retValues);
            FiraUtil.getTag(FiraSpecs.TAG_OID, mem, retValues[1], retValues[2], true, retValues);
            // This is safe i.e. mem is passed in directly, because this will be passed to
            // shareable
            // interface this will copy the memory.
            serviceApplet[ref].init(mem, retValues[3], retValues[2]);
            context.setAppletRef(ref);
        }
        // Applet is plugged in and so dispatch the command.
        return serviceApplet[ref].dispatch(buf, cmdIndex, cmdLen, outBuf, outIndex);
    }

    private void putControleeInfo(byte[] buf, short index, short len, FiraAppletContext context) {
        short tag = FiraUtil.getNextTag(buf, index, len, true, retValues);

        tag = FiraUtil.getTag(FiraSpecs.TAG_UWB_CAPABILITY, buf, retValues[3], retValues[2], false,
                retValues);
        // UWB Capability can only be set in root context.
        if (tag != FiraSpecs.INVALID_VALUE && !context.isRoot()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        tag = FiraUtil.getTag(FiraSpecs.TAG_UWB_REGULATORY_INFO, buf, retValues[3], retValues[2],
                false, retValues);
        // UWB Regular info can only be set in root context.
        if (tag != FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Everything else can be written in a secure context which is checked
        // beforehand.
        if (context.isRoot()) {
            FiraRepository.putSharedDataObject(buf, index, len);
        } else {
            FiraRepository.putData(FiraSpecs.TAG_UWB_CONTROLEE_INFO, buf, index, len,
                    (byte) context.getSlot());
        }
    }

    private void putSessionData(byte[] buf, short index, short len, FiraAppletContext context) {
        // Only possible in remote or local secure state
        if (context.isLocalUnSecure() && context.isRemoteUnSecure()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Add the session data to repository
        FiraRepository.putData(FiraSpecs.TAG_UWB_SESSION_DATA, buf, index, len,
                (byte) context.getSlot());
    }

    // Send the RDS to Sus Applet
    private short sendRDS(byte[] buf, short index, short len) {
        SecureUwbService susApplet = (SecureUwbService) JCSystem
                .getAppletShareableInterfaceObject(
                        new AID(FiraSpecs.SUS_APPLET_AID, (short) 0,
                                (byte) FiraSpecs.SUS_APPLET_AID.length),
                        SecureUwbService.SERVICE_ID);

        return susApplet.createRangingDataSet(buf, index, len, null, (short) 0);
    }

    // TODO this is not required in the FIRAApplet so it is commented for now and
    // still kept in the code
    // as placeholder for future reference.
    /*
     * private short deleteRDS(byte[] buf, short index, short len){ return
     * susApplet.deleteRangingDataSet(buf, index, len, null, (short)0); }
     */

    private void generateAndSendRDS(byte[] buf, short index, short len, FiraAppletContext context) {
        byte[] mem = FiraRepository.getSlotSpecificAdfData(FiraSpecs.TAG_UWB_SESSION_DATA,
                (byte) context.getSlot(), retValues);
        short end = FiraUtil.getTag(FiraSpecs.TAG_UWB_SESSION_DATA, mem, retValues[1], retValues[2],
                true, retValues);

        if (end == FiraSpecs.INVALID_VALUE) {
            return;
        }

        // TAG_UWB_SESSION_DATA is a constructed tag so start next search in 'mem' with
        // TLV value
        short valueLen = retValues[2];
        short valueIndex = retValues[3];

        end = FiraUtil.getTag(FiraSpecs.TAG_UWB_SESSION_ID, mem, retValues[3], valueLen, true,
                retValues);
        if (end == FiraSpecs.INVALID_VALUE) {
            return;
        }

        short sessionIdOffset = retValues[3];
        short configAvailable = FiraUtil.getTag(FiraSpecs.TAG_UWB_CONFIG_AVAILABLE, mem, end,
                (short) (valueLen - (end - valueIndex)), true, retValues);
        if (configAvailable == FiraSpecs.INVALID_VALUE
                && (!context.isAutoTerminate() && context.isDefaultKeyGeneration())) {
            return;
        }

        len = FiraSCHandler.generateRDS(buf, index, len, mem, sessionIdOffset, context);
        sendRDS(buf, index, len);
    }

    private void putServiceData(byte[] buf, short index, short len, FiraAppletContext context) {
        // TODO implement this for local service data management
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    private short handleTunneledCommand(byte[] buf, short index, short len,
            FiraAppletContext context, short[] retValues) {
        retValues[0] = retValues[1] = retValues[2] = retValues[3] = 0;
        short ins = buf[(short) (index + ISO7816.OFFSET_INS)];
        boolean sessionData = false;

        // Only extended apdu are supported
        if (buf[(short) (index + ISO7816.OFFSET_LC)] != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        len = Util.getShort(buf, (short) (index + ISO7816.OFFSET_LC + (short) 1));
        index += ISO7816.OFFSET_EXT_CDATA;

        switch (ins) {
        case FiraSpecs.INS_PUT_DATA:
            assertOrderedStructure(buf, index, len, FiraSpecs.DATA_REMOTE_PUT_DATA, true, buf,
                    (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                    retValues);
            FiraUtil.getNextTag(buf, index, len, true, retValues);
            sessionData = (retValues[1] == FiraSpecs.TAG_UWB_SESSION_DATA);
            len = processPutDataCmd(buf, index, len, context);
            break;
        case FiraSpecs.INS_GET_DATA:
            FiraUtil.getNextTag(buf, index, len, true, retValues);
            // Verify that the instruction has GET Data tag and payload
            if (retValues[1] != FiraSpecs.TAG_GET_CMD || retValues[2] <= 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            FiraUtil.getNextTag(buf, retValues[3], retValues[2], false, retValues);
            index = retValues[3];
            len = retValues[2];
            switch (retValues[1]) {
            case FiraSpecs.TAG_UWB_CONTROLEE_INFO:
                if (len == 0) {
                    len = getAllControleeInfo(buf, index, len, context, retValues);
                } else {
                    len = handleGetCommand(retValues[1], buf, index, len, context, retValues);
                }
                break;
            case FiraSpecs.TAG_UWB_SESSION_DATA:
                len = handleGetCommand(retValues[1], buf, index, len, context, retValues);
                sessionData = true;
                break;
            case FiraSpecs.TAG_SERVICE_DATA:
                len = handleGetCommand(retValues[1], buf, index, len, context, retValues);
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                break;
            }
            index = retValues[0];
            break;
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            break;
        }

        if (sessionData) {
            generateAndSendRDS(buf, (short) (index + len), FiraSpecs.IMPL_MAX_RDS_DATA_SIZE,
                    context);
            // Terminate the session if required.
            if (context.isAutoTerminate()) {
                terminateSession(context);
            }
        }
        retValues[0] = index;
        return len;
    }

    private short getAllControleeInfo(byte[] buf, short index, short len, FiraAppletContext context,
            short[] retValues) {
        // Get handle to slot specific adf
        byte[] adfMem = FiraRepository.getSlotSpecificAdfData(FiraSpecs.TAG_UWB_CONTROLEE_INFO,
                (byte) context.getSlot(), retValues);
        short adfStart = retValues[1];
        short adfLen = retValues[2];
        // Get handle to shared data
        byte[] sharedMem = FiraRepository.getSharedAdfData(FiraSpecs.TAG_UWB_CONTROLEE_INFO,
                retValues);
        short sharedLen = retValues[2];
        short sharedStart = retValues[1];
        short sharedEnd = FiraUtil.getTag(FiraSpecs.TAG_UWB_CONTROLEE_INFO, sharedMem, sharedStart,
                sharedLen, true, retValues);
        sharedStart = retValues[3];
        sharedLen = retValues[2];
        short adfEnd = FiraUtil.getTag(FiraSpecs.TAG_UWB_CONTROLEE_INFO, adfMem, adfStart, adfLen,
                true, retValues);
        adfStart = retValues[3];
        adfLen = retValues[2];
        short end = (short) (index + adfLen + sharedLen + 3);

        if (sharedMem != null) {
            index = pushAdfTag(buf, end, sharedMem, sharedStart, sharedLen,
                    FiraSpecs.TAG_UWB_REGULATORY_INFO);
        }

        if (adfMem != null) {
            index = pushAdfTag(buf, index, adfMem, adfStart, adfLen,
                    FiraSpecs.TAG_UWB_SECURE_RANGING_INFO);
        }

        if (adfMem != null) {
            index = pushAdfTag(buf, index, adfMem, adfStart, adfLen,
                    FiraSpecs.TAG_UWB_STATIC_RANGING_INFO);
        }

        if (adfMem != null) {
            index = pushAdfTag(buf, index, adfMem, adfStart, adfLen,
                    FiraSpecs.TAG_UWB_CONTROLEE_PREF);
        }

        if (sharedMem != null) {
            index = pushAdfTag(buf, index, sharedMem, sharedStart, sharedLen,
                    FiraSpecs.TAG_UWB_CAPABILITY);
        }

        // Version can be present in shared data as well as adf data. Preference is
        // given to shared data
        boolean verPresentInSharedData = true;

        if (sharedMem != null) {
            short curIndex = pushAdfTag(buf, index, sharedMem, sharedStart, sharedLen,
                    FiraSpecs.TAG_UWB_CONTROLEE_INFO_VERSION);
            verPresentInSharedData = curIndex < index;
            index = curIndex;
        }

        if (adfMem != null && !verPresentInSharedData) {
            index = pushAdfTag(buf, index, adfMem, adfStart, adfLen,
                    FiraSpecs.TAG_UWB_CONTROLEE_INFO_VERSION);
        }

        index = FiraUtil.pushBerTagAndLength(buf, index, FiraSpecs.TAG_UWB_CONTROLEE_INFO,
                (short) (end - index));
        retValues[0] = index;
        return (short) (end - index);
    }

    private short handleGetCommand(short tag, byte[] buf, short index, short len,
            FiraAppletContext context, short[] retValues) {
        byte[] mem = FiraRepository.getSlotSpecificAdfData(tag, (byte) context.getSlot(),
                retValues);
        short memStart = retValues[1];
        short memLen = retValues[2];
        short tagEnd = FiraUtil.getTag(tag, mem, memStart, memLen, false, retValues);

        if (tagEnd == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
        memStart = retValues[3];
        memLen = retValues[2];

        boolean sharedControleeInfo = false;
        while (len > 0) {
            index = FiraUtil.getNextTag(buf, index, len, false, retValues);
            if (index == FiraSpecs.INVALID_VALUE) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            tag = retValues[1];
            index = retValues[3];
            len = retValues[2];

            if (retValues[1] == FiraSpecs.TAG_UWB_REGULATORY_INFO
                    || retValues[1] == FiraSpecs.TAG_UWB_CAPABILITY) {
                if (sharedControleeInfo) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                mem = FiraRepository.getSharedAdfData(tag, retValues);
                memStart = retValues[1];
                memLen = retValues[2];
                sharedControleeInfo = true;
            }

            tagEnd = FiraUtil.getTag(tag, mem, memStart, memLen, false, retValues);
            if (tagEnd == FiraSpecs.INVALID_VALUE) {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
            }
            memStart = retValues[3];
            memLen = retValues[2];
        }
        short end = (short) (index + FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE);
        retValues[0] = FiraUtil.pushBERTlv(buf, end, tag, mem, memStart, memLen);
        return (short) (end - retValues[0]);
    }

    private short pushAdfTag(byte[] buf, short index, byte[] mem, short start, short len,
            short tag) {
        // Get the data from adf
        short dataEnd = FiraUtil.getTag(tag, mem, start, len, true, retValues);

        // If it is not present then just return current index
        if (dataEnd == FiraSpecs.INVALID_VALUE) {
            return index;
        }
        // Else push the data from adf in the buf and return the new index
        return FiraUtil.pushBERTlv(buf, index, tag, mem, retValues[3], retValues[2]);
    }

    private short processImportADFCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_IMPORT_ADF_CMD, true, buf,
                (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                retValues);
        // Add Applet specific OID if none is provided
        if (FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true,
                retValues) == FiraSpecs.INVALID_VALUE) {
            // Shift by APPLET_OID bytes
            short aopOidLen = (short) FiraSpecs.TAG_APPLET_OID.length;
            Util.arrayCopyNonAtomic(buf, inputStart, buf, (short) (inputStart + aopOidLen),
                    inputLen);
            Util.arrayCopyNonAtomic(FiraSpecs.TAG_APPLET_OID, (short) 0, buf, inputStart,
                    aopOidLen);
            inputLen += aopOidLen;
        }

        byte[] outBuf = buf;
        short outStart = (short) (inputStart + inputLen + 16); // 16 bytes extra
        // Check if there is enough space in the apdu buf to hold encrypted output and
        // then encrypt
        // using AES block cipher with padding.
        // Padding may add upto one block of padding bytes (16 bytes)
        // IF not then use the cache buf.
        if ((short) (buf.length - outStart) < inputLen) {
            if (isDataCacheFree() && (short) (dataCache.length) >= (short) (inputLen + 16)) {
                outBuf = dataCache;
                outStart = (short) 0;
            } else { // else return error
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }
        retValues[0] = inputStart;
        return encryptAdf(buf, inputStart, outBuf, outStart, inputLen);
    }

    private short processSwapADFCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        byte slot = FiraSpecs.INVALID_VALUE;

        // Acquire
        if (buf[ISO7816.OFFSET_P1] == FiraSpecs.INS_P1_SWAP_ADF_OP_ACQUIRE) {
            // Check the slot
            if (context.getSlot() != FiraSpecs.INVALID_VALUE
                    && context.getSlot() != FiraRepository.ROOT_SLOT) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            // reserve the slot
            slot = (byte) FiraRepository.reserveDynamicSlot();
            if (slot == FiraSpecs.INVALID_VALUE) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }

            try {
                assertOrderedStructure(buf, inputStart, inputLen,
                        FiraSpecs.DATA_SWAP_ADF_ACQUIRE_CMD, true, buf,
                        (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                        retValues);

                // Read secure blob - Static STS is not supported
                short inputEnd = FiraUtil.getNextTag(buf, inputStart, inputLen, true, retValues);
                short secureBlobStart = retValues[3];
                short secureBlobLen = (short) (inputEnd - secureBlobStart);

                // Use data cache if it is free and the apdu buffer is not having enough space
                if (secureBlobLen < (short) (buf.length - inputLen)) {
                    secureBlobLen = decryptAdf(buf, secureBlobStart, buf, inputEnd, secureBlobLen);
                } else if (!flags[DATA_CACHE_IN_USE] && secureBlobLen < dataCache.length) {
                    secureBlobLen = decryptAdf(buf, secureBlobStart, dataCache, (short) 0,
                            secureBlobLen);
                    resetDataCache();
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }

                // Swap Adf is also like local select adf
                context.setSlot(slot);
                // Add the tags from the adf in secure blob
                FiraRepository.addMultipleDataObjects(buf, secureBlobStart, secureBlobLen, slot);
                // Return slot identifier
                buf[inputStart] = slot;
                retValues[0] = inputStart;
                return (short) 1;
            } catch (ISOException e) { // free the slot in case of the exception
                FiraRepository.freeSlot(slot);
                ISOException.throwIt(e.getReason());
            }
        } else if (buf[ISO7816.OFFSET_P1] == FiraSpecs.INS_P1_SWAP_ADF_OP_RELEASE) {
            // Release the ADF
            // Get the slot number
            slot = buf[inputStart];
            // Error if the slot is already free

            if (FiraRepository.isSlotFree(slot)) {
                ISOException.throwIt(FiraSpecs.SLOT_NOT_FOUND);
            }

            // Free The slot
            FiraRepository.freeSlot(slot);
            if (context.getSlot() != FiraSpecs.INVALID_VALUE) {
                context.clearSlot();
            }
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return 0;
    }

    // This does AES ECB encryption. This can be changed if required in the future.
    private short encryptAdf(byte[] buf, short inputStart, byte[] outBuf, short outStart,
            short inputLen) {
        Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        cipher.init(masterKey, Cipher.MODE_ENCRYPT);

        // PKCS7 padding
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

    // This does AES ECB encryption. This can be changed if required in the future.
    private short decryptAdf(byte[] buf, short inputStart, byte[] outBuf, short outStart,
            short inputLen) {
        Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        cipher.init(masterKey, Cipher.MODE_DECRYPT);
        inputLen = cipher.doFinal(buf, inputStart, inputLen, outBuf, outStart);
        // remove padding
        inputLen -= outBuf[(short) (outStart + inputLen - 1)];
        // Copy back the data to input vector
        Util.arrayCopyNonAtomic(outBuf, outStart, buf, inputStart, inputLen);
        return inputLen;
    }

    public boolean select(boolean b) {
        return true;
    }

    public void deselect(boolean b) {
    }

    public boolean select() {
        return true;
    }

    public void deselect() {
        FiraAppletContext.getContext(APDU.getCLAChannel()).reset();
    }

    public void uninstall() {
        // Do nothing.
    }

    private short processInitTransaction(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        // The ADF must already be selected
        if (context.getSlot() == FiraSpecs.INVALID_VALUE && !context.isRoot()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Decode
        assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_INITIATE_TRANSACTION, true,
                buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                retValues);

        // validate the OIDs - there will be only one or only the first one will always
        // be the
        // selected adf.
        short oidEnd = FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true,
                retValues);
        short oidStart = retValues[0];
        short oidLen = (short) (oidEnd - oidStart);
        context.setSecureChannel(
                FiraSecureChannel.create(FiraSecureChannel.FIRA_SC_PROTOCOL, context));

        // Initiate the flow which will create select command.
        // The framework has to route it to correct peer device
        inputLen = FiraSCHandler.initiate(FiraSpecs.FIRA_APPLET_AID, (short) 0,
                (short) FiraSpecs.FIRA_APPLET_AID.length, buf, inputStart, inputLen, buf, oidStart,
                oidLen, context);
        inputStart = pushDispatchResponse(buf, inputStart, inputLen,
                FiraSpecs.VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER, FiraAppletContext.EVENT_INVALID,
                null, FiraSpecs.INVALID_VALUE, (short) 0, retValues);
        inputLen = retValues[0];
        retValues[0] = inputStart;
        return inputLen;
    }

    public short wrap(byte[] buf, short index, short len, FiraAppletContext context) {
        return FiraSCHandler.wrap(buf, index, len, context);
    }

    public short unwrap(byte[] buf, short index, short len, FiraAppletContext context) {
        return FiraSCHandler.unwrap(buf, index, len, context);
    }

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

        if (context.getAppletRef() != FiraSpecs.INVALID_VALUE
                && serviceApplet[context.getAppletRef()].isReserved()) {
            serviceApplet[context.getAppletRef()].cleanUp();
            context.setAppletRef(FiraSpecs.INVALID_VALUE);
        }
        // TODO uncomment the following for JCOP version
        // Release the references
        // JCSystem.requestObjectDeletion();
    }

    // -------------------------------- Establish local Scp11c Secure channel Apdu

    // This method is different from rest of the process methods. This method treats
    // buf as apdu
    // because it handles also P1 and P2. So care must be taken that complete apdu
    // buf is passed to
    // this method.
    private short processScp11cCmd(byte[] buf, short index, short len, FiraAppletContext context,
            short[] retValues) {
        // If no slot is selected before establishing the channel then always select the
        // root slot default.
        if (context.getSlot() == FiraSpecs.INVALID_VALUE) {
            context.setRoot();
        }

        if (context.getSecureChannel() == null) {
            context.setSecureChannel(
                    FiraSecureChannel.create(FiraSecureChannel.FIRA_SCP11c_PROTOCOL, context));
        }

        // handle the complete protocol object - start offset in buf is 0.
        len = FiraSCHandler.handleProtocolObject(buf, (short) 0,
                (short) (len + ISO7816.OFFSET_EXT_CDATA), context);
        retValues[0] = index;

        // if secure session is established then update the context accordingly
        if (FiraSCHandler.isSecure(context)) {
            context.setLocalSecureState(FiraAppletContext.LOCAL_SECURE);
        }
        return len;
    }

    // -- Static Slot related local management Apdu
    private short processDeleteAdfCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        byte slotId = (byte) context.getSlot();
        // Is there a selected slot - then free that slot and ignore OId.

        if (slotId != FiraSpecs.INVALID_VALUE && slotId != FiraRepository.ROOT_SLOT
                && slotId != FiraRepository.APPLET_SLOT) {
            context.clearSlot();
            FiraRepository.freeSlot(slotId);
        } else if (inputLen != 0) { // No slot/ADF selected - OID must be given
            // validate input
            assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_DELETE_ADF_CMD, true,
                    buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                    retValues);
            // get oid
            short oidEnd = FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true,
                    retValues);
            short oidStart = retValues[0];
            short oidLen = (short) (oidEnd - oidStart);
            // free the slot using oid
            slotId = FiraRepository.getSlot(buf, oidStart, oidLen);

            if (slotId == FiraSpecs.INVALID_VALUE) {
                ISOException.throwIt(FiraSpecs.OID_NOT_FOUND);
            } else {
                // Cannot delete ADF if it is being used i.e. it is selected by another channel
                if (FiraRepository.isSlotSelected(slotId)) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                FiraRepository.freeSlot(slotId);
            }
            // no response required
        } else {// neither adf selected nor oid given
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        return 0;
    }

    // Manage Adf is the only method that requires internal memory.
    private short processManageADFCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        // Handle the instruction
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
        } else if (buf[ISO7816.OFFSET_P1] == FiraSpecs.INS_MANAGE_ADF_FINISH_P1) { // last manage
                                                                                   // adf and so
                                                                                   // commit the adf
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
            assertOrderedStructure(cache, dataStart, dataLen, FiraSpecs.DATA_MANAGE_ADF_CMD, true,
                    buf, (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                    retValues);
            JCSystem.beginTransaction();
            FiraRepository.addMultipleDataObjects(cache, dataStart, dataLen, (byte) slot);
            JCSystem.commitTransaction();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return 0;
    }

    private short processCreateAdfCmd(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        // Context should have root slot to begin with because create adf cannot be done
        // in slot
        // specific way.
        if (context.getSlot() != FiraRepository.ROOT_SLOT) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Reserve a static slot. Note: we do not set the slot in context because there
        // can be multiple
        // create adfs for each static slot. Before manage adf there will be select adf.
        byte slot = (byte) FiraRepository.reserveStaticSlot();
        if (slot == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_CREATE_ADF, true, buf,
                (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                retValues);

        // Check whether the OID already present in the repository
        retValues[4] = FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true,
                retValues);

        short existSlot = FiraRepository.getSlot(buf, retValues[0],
                (short) (retValues[4] - retValues[0]));
        // If Oid already present then free the slot and return error.
        if (existSlot != FiraSpecs.INVALID_VALUE) {
            FiraRepository.freeSlot(slot);
            ISOException.throwIt(FiraSpecs.OID_ALREADY_PRESENT);
        }

        // Replace ADF Provisioning tag with internal tag.
        // This is done because ADF Provisioning Credentials tag and Fira SC Credentials
        // tags are the
        // same in the Fira Specs. It is not clear whether this is intentional.
        short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_ADF_PROVISIONING_CRED, buf, inputStart,
                inputLen, true, retValues);
        if (tagEnd != FiraSpecs.INVALID_VALUE) {
            Util.setShort(buf, retValues[0], FiraSpecs.TAG_STORED_ADF_PROVISIONING_CRED);
        }

        // Create the Adf.
        JCSystem.beginTransaction();
        FiraRepository.addMultipleDataObjects(buf, inputStart, inputLen, slot);
        JCSystem.commitTransaction();
        return 0;
    }

    // TODO can we reuse the method in FiraSC?
    private short processSelectAdf(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        // There should not be already selected slot or if at all it should be root
        // slot.
        if (context.getSlot() != FiraSpecs.INVALID_VALUE
                && context.getSlot() != FiraRepository.ROOT_SLOT) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // Select first OID in the list of OIDs.
        short randomDataEnd = FiraUtil.getTag(FiraSpecs.TAG_RANDOM_DATA_1_2, buf, inputStart,
                inputLen, true, retValues);
        if (randomDataEnd == FiraSpecs.INVALID_VALUE || retValues[2] != (byte) 16) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short randStart = retValues[0];
        short oidEnd = FiraUtil.getTag(FiraSpecs.TAG_OID, buf, inputStart, inputLen, true,
                retValues);
        if (oidEnd == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // Get the slot for the OID
        short oidStart = retValues[0];
        byte slot = FiraRepository.getSlot(buf, oidStart, (short) (oidEnd - oidStart));
        if (slot == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(FiraSpecs.OID_ALREADY_PRESENT);
        }
        // Set the slot in the current context.
        context.setSlot(slot);
        inputStart = (randomDataEnd > oidEnd) ? randomDataEnd : oidEnd;

        // make and return response
        short end = makeSelectResponse(buf, oidStart, oidEnd, randStart, randomDataEnd, inputStart);
        inputLen = (short) (end - inputStart);
        retValues[0] = inputStart;
        return inputLen;
    }

    private short makeSelectResponse(byte[] buf, short oidStart, short oidEnd, short randStart,
            short randEnd, short index) {
        byte[] mem = FiraRepository.getAppletData(FiraSpecs.TAG_DEVICE_UID, retValues);

        if (mem == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short deviceUidEnd = FiraUtil.getTag(FiraSpecs.TAG_DEVICE_UID, mem, retValues[1],
                retValues[2], true, retValues);
        if (deviceUidEnd == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short deviceUidStart = retValues[3];
        short deviceUidLen = retValues[2];
        short oidLen = (short) (oidEnd - oidStart);
        short randLen = (short) (randEnd - randStart);
        index = Util.arrayCopyNonAtomic(FiraSpecs.SELECT_ADF_ALGORITHM_INFO, (short) 0, buf, index,
                (short) FiraSpecs.SELECT_ADF_ALGORITHM_INFO.length);
        index = Util.arrayCopyNonAtomic(buf, oidStart, buf, index, oidLen);
        buf[index++] = (byte) FiraSpecs.TAG_DIVERSIFIER;
        buf[index++] = (byte) deviceUidLen;
        index = Util.arrayCopyNonAtomic(mem, deviceUidStart, buf, index, deviceUidLen);
        index = Util.arrayCopyNonAtomic(buf, randStart, buf, index, randLen);
        return index;
    }

    // -----Following methods can be replaced by Store Data Apdu
    private short processProvisionSDCredentials(byte[] buf, short inputStart, short inputLength,
            FiraAppletContext context, short[] retValues) {
        // TODO We just check presence of tags but we do not validate cert.
        short tagEnd = FiraUtil.getNextTag(buf, inputStart, inputLength, true, retValues);

        if (tagEnd == FiraSpecs.INVALID_VALUE || retValues[1] != FiraSpecs.TAG_APPLET_CERT_STORE) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short tagStart = retValues[3];
        short tagLen = retValues[2];
        tagEnd = FiraUtil.getTag(FiraSpecs.TAG_CERT, buf, tagStart, tagLen, true, retValues);

        if (tagEnd != FiraSpecs.INVALID_VALUE) {
            tagEnd = FiraUtil.getTag(FiraSpecs.TAG_DEVICE_UID, buf, inputStart, inputLength, true,
                    retValues);
            if (tagEnd != FiraSpecs.INVALID_VALUE) {
                tagEnd = FiraUtil.getTag(FiraSpecs.TAG_APPLET_SECRET, buf, inputStart, inputLength,
                        true, retValues);
            }
        }

        if (tagEnd == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        FiraRepository.putAppletDataObject(FiraSpecs.TAG_APPLET_CERT_STORE, buf, inputStart,
                inputLength);
        return 0;
    }

    private short processProcessPACredentials(byte[] buf, short index, short len,
            FiraAppletContext context, short[] retValues) {
        short tagEnd = FiraUtil.getNextDGITag(buf, index, len, true, retValues);

        if (tagEnd == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        switch (retValues[1]) {
        case FiraSpecs.TAG_ADD_REPLACE_PA_CREDENTIALS:
            addPACredentials(buf, retValues[3], retValues[2]);
            break;
        case FiraSpecs.TAG_ERASE_PA_CREDENTIALS:
            removePACredentials(buf, retValues[3], retValues[2]);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        return 0;
    }

    private void addPACredentials(byte[] buf, short inputStart, short inputLen) {
        assertOrderedStructure(buf, inputStart, inputLen, FiraSpecs.DATA_PA_RECORD, true, buf,
                (short) (IMPL_APDU_BUFFER_MAX_SIZE - FiraSpecs.IMPL_SCRATCH_PAD_MAX_SIZE),
                retValues);
        // Read the tag to add
        short valEnd = FiraUtil.getNextTag(buf, inputStart, inputLen, true, retValues);
        short valStart = retValues[0];
        byte[] mem = FiraRepository.getSharedAdfData(FiraSpecs.TAG_PA_RECORD, retValues);
        short memStart = retValues[1];
        short memLen = retValues[2];

        // search the records.
        short recordEnd = FiraUtil.search(FiraSpecs.TAG_PA_RECORD, FiraSpecs.TAG_PA_CRED_PA_ID, buf,
                valStart, (short) (valEnd - valStart), mem, memStart, memLen, retValues);
        // error if the record exists
        if (recordEnd != FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Add the PA Record tag - we will have at least 7 bytes in front.
        short index = inputStart;
        inputStart = FiraUtil.pushBERLength(buf, inputStart, inputLen);
        inputStart = FiraUtil.pushBERTag(buf, inputStart, FiraSpecs.TAG_PA_RECORD);
        inputLen += (short) (index - inputStart);
        // add the record
        FiraRepository.putSharedDataObject(buf, inputStart, inputLen);
    }

    private void removePACredentials(byte[] buf, short inputStart, short inputLen) {
        // Get the PA Record file.
        byte[] mem = FiraRepository.getSharedAdfData(FiraSpecs.TAG_PA_RECORD, retValues);
        short memMaxLen = retValues[0];
        short memStart = retValues[1];
        short memLen = retValues[2];

        // search the records for given PA Identifier
        short recordEnd = FiraUtil.search(FiraSpecs.TAG_PA_RECORD, FiraSpecs.TAG_PA_CRED_PA_ID, buf,
                inputStart, inputLen, mem, memStart, memLen, retValues);
        // erase the record if it exists
        if (recordEnd != FiraSpecs.INVALID_VALUE) {
            JCSystem.beginTransaction();
            FiraRepository.perform(FiraRepository.DELETE, mem, memStart, memLen, memMaxLen,
                    retValues[0], (short) (recordEnd - retValues[0]), null, (short) 0, (short) 0);
            JCSystem.commitTransaction();
        }
    }

    private short processProvisionServiceApplet(byte[] buf, short inputStart, short inputLen,
            FiraAppletContext context, short[] retValues) {
        switch (buf[ISO7816.OFFSET_P1]) {
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
        return 0;
    }

    private void plugOutServiceApplet(byte[] buf, short inputStart, short inputLen) {
        short index = getServiceApplet(buf, inputStart, (byte) inputLen);

        if (index == FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        serviceApplet[index].delete();
        serviceApplet[index] = null;
        JCSystem.requestObjectDeletion();
    }

    private void plugInServiceApplet(byte[] buf, short inputStart, short inputLen) {
        if (getServiceApplet(buf, inputStart, (byte) inputLen) != FiraSpecs.INVALID_VALUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte len = (byte) serviceApplet.length;
        byte index = 0;
        while (index < len) {
            if (serviceApplet[index] == null) {
                serviceApplet[index] = new FiraServiceAppletHandler(buf, inputStart,
                        (byte) inputLen);
                return;
            }
            index++;
        }
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    private byte getServiceApplet(byte[] buf, short inputStart, byte inputLen) {
        byte len = (byte) serviceApplet.length;
        byte index = 0;

        while (index < len) {
            if (serviceApplet[index] != null
                    && serviceApplet[index].isAppletIdEquals(buf, inputStart, inputLen)) {
                return index;
            }
            index++;
        }
        return FiraSpecs.INVALID_VALUE;
    }
}
