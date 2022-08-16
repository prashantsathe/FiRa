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

import com.android.javacard.SecureChannels.FiraClientContext;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * This class provides channel specific context - selected slot, state and any
 * state specific data. There will be one instance of this class per logical
 * channel.
 */
public class FiraAppletContext extends FiraClientContext {

    // Total number of logical channels supported - each will have a context
    public static final byte IMPL_MAX_LOGICAL_CHANNELS = 20;
    // Extended Options masks
    public static final byte EXT_OPTIONS_TERMINATE = (byte) 0x80;
    public static final byte EXT_OPTIONS_PRIVACY = (short) 0x40;
    public static final byte EXT_OPTIONS_SESSION_KEY = (byte) 0x80;
    public static final byte EXT_OPTIONS_DERIVE_KEY = (byte) 0xA0;
    // Remote Secure Channel sub-states - for SC1 and SC2
    public static final byte REMOTE_UNSECURE = (byte) 0;
    public static final byte REMOTE_SECURE = (byte) 0x02;
    // Local Secure Channel sub-states - for SCP11c
    public static final byte LOCAL_UNSECURE = (byte) 0x00;
    public static final byte LOCAL_SECURE = (byte) 0x01;
    // Asynchronous Operation states
    public static final byte OP_IDLE = (byte) 0;
    public static final byte OP_TUNNEL_ACTIVE = (byte) 1;
    // Asynchronous sub-operation state for tunneled command
    public static final byte OP_TERMINATE_SESSION = (byte) 0x40;
    public static final byte OP_GET_SESSION_DATA = (byte) 0x20;
    public static final byte OP_PUT_SESSION_DATA = (byte) 0x10;
    public static final byte OP_STATE_MASK = (byte) 0x0F;
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
    // Context table - one per logical channel
    private static Object[] contexts;
    private static short[] retValues;

    // instance attributes
    private final byte[] attributes;
    private final Object[] dataCache;
    private final Object[] secureChannel;

    private FiraAppletContext() {
        attributes = JCSystem.makeTransientByteArray(ATTRIBUTES_COUNT, JCSystem.CLEAR_ON_RESET);
        dataCache = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
        secureChannel = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
        retValues = JCSystem.makeTransientShortArray((short) 5, JCSystem.CLEAR_ON_RESET);
        reset();
    }

    public static void init() {
        byte channels = IMPL_MAX_LOGICAL_CHANNELS;
        contexts = new Object[channels];

        while (channels > 0) {
            channels--;
            contexts[channels] = new FiraAppletContext();
        }
    }

    public static short getChannelCnt() {
        return IMPL_MAX_LOGICAL_CHANNELS;
    }

    public static FiraAppletContext getContext(short channel) {
        return (FiraAppletContext) contexts[channel];
    }

    public Object getSecureChannel() {
        return secureChannel[0];
    }

    public void setSecureChannel(Object channel) {
        secureChannel[0] = channel;
    }

    public void reset() {
        attributes[SLOT] = FiraSpecs.INVALID_VALUE;
        attributes[LOCAL_CHANNEL_STATE] = LOCAL_UNSECURE;
        attributes[REMOTE_CHANNEL_STATE] = REMOTE_UNSECURE;
        attributes[OPERATION_STATE] = OP_IDLE;
        attributes[EXTENDED_OPTIONS_BYTE_1] = 0;
        attributes[EXTENDED_OPTIONS_BYTE_2] = 0;
        attributes[EVENT] = FiraClientContext.EVENT_INVALID;
        attributes[APPLET_REF] = FiraSpecs.INVALID_VALUE;
    }

    public byte getAppletRef() {
        return attributes[APPLET_REF];
    }

    public short setAppletRef(byte appletRef) {
        return attributes[APPLET_REF] = appletRef;
    }

    public short getSlot() {
        if (attributes[SLOT] < 0) {
            return FiraSpecs.INVALID_VALUE;
        } else {
            return attributes[SLOT];
        }
    }

    public void setSlot(byte slot) {
        attributes[SLOT] = slot;
        FiraRepository.selectAdf(slot);
    }

    public boolean isRoot() {
        return getSlot() == FiraRepository.ROOT_SLOT;
    }

    public void setRoot() {
        attributes[SLOT] = FiraRepository.ROOT_SLOT;
    }

    public void clearRoot() {
        attributes[SLOT] = FiraSpecs.INVALID_VALUE;
    }

    public void clearSlot() {
        if (attributes[SLOT] != FiraSpecs.INVALID_VALUE) {
            FiraRepository.deselectAdf(attributes[SLOT]);
        }
        attributes[SLOT] = FiraSpecs.INVALID_VALUE;
    }

    public boolean isLocalSecure() {
        return attributes[LOCAL_CHANNEL_STATE] == LOCAL_SECURE;
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

    public short getLocalChannelState() {
        return attributes[LOCAL_CHANNEL_STATE];
    }

    public short getRemoteChannelState() {
        return attributes[REMOTE_CHANNEL_STATE];
    }

    public void setLocalSecureState(byte secureState) {
        attributes[LOCAL_CHANNEL_STATE] = secureState;
    }

    public void setRemoteSecureState(byte secureState) {
        attributes[REMOTE_CHANNEL_STATE] = secureState;
    }

    public byte[] getDataCache() {
        return (byte[]) dataCache[0];
    }

    public void associateDataCache(byte[] cache) {
        dataCache[0] = cache;
    }

    public short getOpState() {
        return (byte) (attributes[OPERATION_STATE] & OP_STATE_MASK);
    }

    public void setOpState(byte opState) {
        attributes[OPERATION_STATE] = (byte) (attributes[OPERATION_STATE] | opState);
    }

    public void clearOperationState() {
        attributes[OPERATION_STATE] = OP_IDLE;
    }

    public void clearTerminateSessionOpState() {
        attributes[OPERATION_STATE] = (byte) (attributes[OPERATION_STATE] & (byte) 0x00BF);
    }

    public void setExtOptions(short extOpts) {
        attributes[EXTENDED_OPTIONS_BYTE_1] = (byte) ((extOpts & (short) 0xFF00) >> 8);
        attributes[EXTENDED_OPTIONS_BYTE_2] = (byte) (extOpts & (short) 0x00FF);
    }

    public boolean isAutoTerminate() {
        return (attributes[EXTENDED_OPTIONS_BYTE_1] & EXT_OPTIONS_TERMINATE) != 0;
    }

    public boolean isPrivacyEnforced() {
        return (attributes[EXTENDED_OPTIONS_BYTE_1] & EXT_OPTIONS_PRIVACY) != 0;
    }

    public boolean isDefaultKeyGeneration() {
        return (attributes[EXTENDED_OPTIONS_BYTE_2] & EXT_OPTIONS_SESSION_KEY) == 0;
    }

    public boolean isSessionKeyUsedForDerivation() {
        return (attributes[EXTENDED_OPTIONS_BYTE_2] & EXT_OPTIONS_DERIVE_KEY) != 0;
    }

    // Input is OId. Returns set of KVNs if the adf identified by the oid can be
    // selected else it
    // returns null.This method is implemented based on an understanding that just
    // like initiator the
    // responder may or may not have static adf slot and the oid received in select
    // adf command may
    // refer the swapped dynamic slot adf. There are two cases: first case is that
    // oid is found
    // in static slot - in this case the context must not have any selected slot.
    // The second case is
    // that context has dynamic slot i.e. swapped in adf and selected adf is routed
    // to that. In this
    // case the slot in the context must match that in select adf.
    public boolean selectAdf(byte[] oidBuf, short start, short len) {
        byte slot = FiraRepository.getSlotUsingOid(oidBuf, start, len);
        if (slot != FiraSpecs.INVALID_VALUE && getSlot() == FiraSpecs.INVALID_VALUE) {
            setSlot(slot);
            return true;
        }
        return slot != FiraSpecs.INVALID_VALUE && slot == getSlot();
    }

    public short getSelectedKvn(byte kvnType, byte[] buf, short index) {
        byte[] mem = FiraRepository.getSlotSpecificAdfData(FiraSpecs.TAG_FIRA_SC_CRED,
                (byte) getSlot(), retValues);
        short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_CRED, mem, retValues[1], retValues[2],
                false, retValues);
        short start = retValues[3];
        short len = retValues[2];

        switch (kvnType) {
        case PRIVACY_KEY_SET:
            buf[index] = (byte) FiraSpecs.VAL_SC1_PRIVACY_KEY_SET;
            tagEnd = FiraUtil.search(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_KEY_SET,
                    FiraSpecs.TAG_FIRA_SC_CH_ID, buf, index, (short) 1, mem, start, len, retValues);

            if (tagEnd == FiraSpecs.INVALID_VALUE) {
                buf[index] = (byte) FiraSpecs.VAL_SC2_PRIVACY_KEY_SET;
                tagEnd = FiraUtil.search(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_KEY_SET,
                        FiraSpecs.TAG_FIRA_SC_CH_ID, buf, index, (short) 1, mem, start, len,
                        retValues);
            }
            break;
        case SC_KEY_SET:
            tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_KEY_SET, mem, start, len, true,
                    retValues);
            if (tagEnd == FiraSpecs.INVALID_VALUE) {
                tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_ASYMMETRIC_KEY_SET, mem, start, len,
                        true, retValues);
            }
            break;
        case BASE_KEY_SET:
            tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_BASE_KEY, mem, start, len,
                    true, retValues);
            break;
        case UWB_ROOT_KEY_SET:
            tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_UWB_RANGING_ROOT_KEY, mem, start, len,
                    true, retValues);
            break;

        }

        if (tagEnd == FiraSpecs.INVALID_VALUE) {
            return 0;
        } else {
            Util.arrayCopyNonAtomic(mem, retValues[0], buf, index, (short) (tagEnd - retValues[0]));
            return (short) (tagEnd - retValues[0]);
        }
    }

    // Input is key set kvn and output is key set. If the key set is not found then
    // it
    // returns INVALID_VAL else key set is copied in the buf starting at index and
    // returns the length
    // of the key set. Key set is copied in BER TLV format, starting with key set
    // tag as defined in
    // FiraApplet Specifications.
    public short getKeySet(short kvn, byte[] buf, short index) {
        byte[] mem = FiraRepository.getSlotSpecificAdfData(FiraSpecs.TAG_FIRA_SC_CRED,
                (byte) getSlot(), retValues);
        buf[index] = (byte) kvn;
        short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_FIRA_SC_CRED, mem, retValues[1], retValues[2],
                false, retValues);
        short start = retValues[3];
        short len = retValues[2];
        tagEnd = FiraUtil.search(FiraSpecs.TAG_FIRA_SC_SYMMETRIC_KEY_SET, FiraSpecs.TAG_FIRA_SC_KVN,
                buf, index, (short) 1, mem, start, len, retValues);

        if (tagEnd == FiraSpecs.INVALID_VALUE) {
            tagEnd = FiraUtil.search(FiraSpecs.TAG_FIRA_SC_ASYMMETRIC_KEY_SET,
                    FiraSpecs.TAG_FIRA_SC_KVN, buf, index, (short) 1, mem, start, len, retValues);
            if (tagEnd == FiraSpecs.INVALID_VALUE) {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
            }
        }
        Util.arrayCopyNonAtomic(mem, retValues[0], buf, index, (short) (tagEnd - retValues[0]));
        return retValues[2];
    }

    // TODO Currently we do not support ADF Provisioning scenario used by Manage
    // ADF. This will be supported once the use-case becomes clear.
    public short getCAPublicKey(byte kvn, byte[] buf, short index) {
        short ret = 0;

        if (getSlot() == FiraRepository.APPLET_SLOT
                || attributes[SLOT] == FiraRepository.ROOT_SLOT) {
            byte[] mem = FiraRepository.getSharedAdfData(FiraSpecs.TAG_PA_RECORD, retValues);

            ret = getPublicKey(mem, retValues[1], retValues[2], FiraSpecs.TAG_PA_RECORD,
                    FiraSpecs.TAG_PA_CRED_PA_ID, kvn, FiraSpecs.TAG_PA_CRED_PA_CREDS, buf, index);
        } else {
            byte[] mem = FiraRepository.getSlotSpecificAdfData(
                    FiraSpecs.TAG_STORED_ADF_PROVISIONING_CRED, (byte) getSlot(), retValues);
            // First read the cred record which may have more than one key sets
            short end = FiraUtil.getTag(FiraSpecs.TAG_STORED_ADF_PROVISIONING_CRED, mem,
                    retValues[1], retValues[2], true, retValues);

            if (end == FiraSpecs.INVALID_VALUE) {// ADF Provisioning Credentials are not defined.
                return 0;
            }

            short start = retValues[3];
            short len = retValues[2];
            ret = getPublicKey(mem, start, len, FiraSpecs.TAG_ADF_PROV_ASYMMETRIC_KEY_SET,
                    FiraSpecs.TAG_ADF_PROV_SEC_CH_KVN, kvn, FiraSpecs.TAG_ADF_PROV_CA_PUB_KEY, buf,
                    index);
            if (ret > 0) {
                end = FiraUtil.getTag(FiraSpecs.TAG_ADF_PROV_SEC_CH_ID, mem, start, len, true,
                        retValues);
                if (end == FiraSpecs.INVALID_VALUE
                        || mem[retValues[3]] != FiraSpecs.VAL_GP_SCP11c) {
                    return (short) 0;
                }
            }
        }
        return ret;
    }

    private short getPublicKey(byte[] mem, short memStart, short memLen, short keySetTag,
            short keySetKvnTag, byte kvn, short credTag, byte[] buf, short start) {
        // Save kvn
        buf[start] = kvn;
        // Search for key set with given kvn
        short end = FiraUtil.search(keySetTag, keySetKvnTag, buf, start, (short) 1, mem, memStart,
                memLen, retValues);
        memStart = retValues[3];
        memLen = retValues[2];
        // Get the credentials
        end = FiraUtil.getTag(credTag, mem, memStart, memLen, true, retValues);

        if (end == FiraSpecs.INVALID_VALUE) {
            return FiraSpecs.INVALID_VALUE;
        }
        Util.arrayCopyNonAtomic(mem, retValues[3], buf, start, retValues[2]);
        return retValues[2];
    }

    public short getSDCertificate(byte[] buf, short index) {
        byte[] mem = FiraRepository.getAppletData(FiraSpecs.TAG_CERT, retValues);
        short end = FiraUtil.getTag(FiraSpecs.TAG_CERT, mem, retValues[1], retValues[2], true,
                retValues);
        short len = (short) (end - retValues[0]);

        if (end == FiraSpecs.INVALID_VALUE) {
            Util.arrayCopyNonAtomic(mem, retValues[0], buf, index, len);
        }
        return len;
    }

    public short getSDSecretKey(byte[] buf, short index) {
        byte[] mem = FiraRepository.getAppletData(FiraSpecs.TAG_APPLET_SECRET, retValues);
        short end = FiraUtil.getTag(FiraSpecs.TAG_APPLET_SECRET, mem, retValues[1], retValues[2],
                true, retValues);

        // This must never happen if the provisioning is done properly.
        if (end == FiraSpecs.INVALID_VALUE) {
            return FiraClientContext.INVALID_VALUE;
        }
        Util.arrayCopyNonAtomic(mem, retValues[3], buf, index, retValues[2]);
        return retValues[2];
    }

    public short getPendingEvent() {
        return attributes[EVENT];
    }

    public void signal(short eventId) {
        attributes[EVENT] = (byte) eventId;
    }

    public void clearPendingEvent() {
        attributes[EVENT] = EVENT_INVALID;
    }

    public void enableGetSessionDataOpState() {
        attributes[OPERATION_STATE] = (byte) (attributes[OPERATION_STATE] | OP_GET_SESSION_DATA);
    }

    public void enablePutSessionDataOpState() {
        attributes[OPERATION_STATE] = (byte) (attributes[OPERATION_STATE] | OP_PUT_SESSION_DATA);
    }

    public boolean isGetSessionData() {
        return (byte) (attributes[OPERATION_STATE] & OP_GET_SESSION_DATA) != 0;
    }

    public boolean isPutSessionData() {
        return (byte) (attributes[OPERATION_STATE] & OP_PUT_SESSION_DATA) != 0;
    }

    public void enableTerminateSessionOpState() {
        attributes[OPERATION_STATE] = (byte) (attributes[OPERATION_STATE] | OP_TERMINATE_SESSION);
    }

    public boolean isTerminateSession() {
        return (byte) (attributes[OPERATION_STATE] & OP_TERMINATE_SESSION) != 0;
    }
}
