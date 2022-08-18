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
package com.android.javacard.SecureChannels;

import static com.android.javacard.SecureChannels.FiraConstant.*;
import static com.android.javacard.SecureChannels.ScpConstant.*;
import static com.android.javacard.SecureChannels.FiraContext.*;

import com.android.javacard.ber.BerTlvBuilder;
import com.android.javacard.ber.BerTlvParser;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;

public class FiraSC extends FiraSecureChannel {

    private static KeyPair sEcKeyPair;
    private static BerTlvBuilder sBerTlvBuilder;

    private static Crypto sCrypto;
    private static Certificates sCertificates;
    private static byte[] sInData;
    private static byte[] sOutData;

    private FiraClientContext mFiraClientContext;
    private FiraContext mContext;

    private Scp3Lib mScp3Lib;
    private FiraCommon mCommon;
    private FiraInitiator mInitiator;
    private FiraResponder mResponder;

    private void InitStaticFields() {
        // Check just one field for NULL
        if (sInData == null) {
            sEcKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            sBerTlvBuilder = new BerTlvBuilder();

            sCrypto = new Crypto();
            sCertificates = new Certificates();
            Crypto.initECKey(sEcKeyPair);

            sInData = JCSystem.makeTransientByteArray((short) IN_DATA_SIZE,
                    JCSystem.CLEAR_ON_RESET);
            sOutData = JCSystem.makeTransientByteArray((short) OUT_DATA_SIZE,
                    JCSystem.CLEAR_ON_RESET);
        }
    }

    public FiraSC(FiraClientContext clientContext) {
        // TODO: Check if clientContext is same for all the instances
        mFiraClientContext = clientContext;
        mContext = new FiraContext();
        InitStaticFields();

        // Create devices
        mScp3Lib = new Scp3Lib(sCrypto);
        mCommon = new FiraCommon(mContext, sCrypto, mScp3Lib);
        mInitiator = new FiraInitiator(mContext, mFiraClientContext, sCrypto, sEcKeyPair,
                mScp3Lib, mCommon, sInData, sOutData);
        mResponder = new FiraResponder(mContext, mFiraClientContext, sCrypto, sEcKeyPair,
                mScp3Lib, sCertificates, sBerTlvBuilder, mCommon, sInData, sOutData);
    }

    private short getKvn(byte[] buf, short bufOffset, short bufLen) {
        if (bufLen > 0) {
            short kvnOffset = ClientContext.getTagValueOffset((byte) TAG_KVN, buf, bufOffset,
                    bufLen);
            if (kvnOffset != INVALID_VALUE) {
                return buf[kvnOffset];
            }
        }
        return INVALID_VALUE;
    }

    // get Select
    private static final short getSelect(byte[] buffer, short bufferOffset, byte[] aidBuff,
            short aidBuffOffset, short aidBuffLength) {

        short index = bufferOffset;

        // CLA/INS/P1P2
        buffer[index++] = C_00;
        buffer[index++] = INS_SELECT;
        buffer[index++] = C_04;
        buffer[index++] = C_00;

        buffer[index++] = C_00; // Extended APDU
        index = Util.setShort(buffer, index, aidBuffLength);

        index = Util.arrayCopyNonAtomic(aidBuff, aidBuffOffset, buffer, index, aidBuffLength);
        buffer[index++] = C_00;
        return (short) (index - bufferOffset);
    }

    private static final boolean verifySelect(byte[] buffer, short bufferOffset) {
        // FCI is optional
        return true;
    }

    private boolean verifySelectADFResponseSC1(byte[] buffer, short bufferOffset) {
        return true;
    }

    private boolean verifyGA1ResponseSC1(byte[] buffer, short bufferOffset) {

        short index = bufferOffset;

        if (buffer[index++] != T_7C || buffer[index++] != (byte) 0x12 ||
                buffer[index++] != T_81 || buffer[index++] != (byte) 0x10) {
            return false;
        }

        Util.arrayCopyNonAtomic(buffer, index, mContext.mBuf, O_RANDOM_ICC, BlOCK_16BYTES);
        return true;
    }

    private boolean verifyGA2ResponseSC1(byte[] buffer, short bufferOffset) {

        short index = bufferOffset;
        short cryptoICCLen = 0;
        short sc1TagNumber = Util.getShort(mContext.mBuf, O_SC1_TAGNUMBER);

        if (buffer[index++] == T_7C) {

            index += BerTlvParser.getTotalLengthBytesCount(buffer, index);

            if (buffer[index++] == T_82) {

                cryptoICCLen = BerTlvParser.getDataLength(buffer, index);
                index += BerTlvParser.getTotalLengthBytesCount(buffer, index);

                // Note: The Secure Messaging Authentication Key consists of KENC
                // (used for encryption) and KMAC(used for authentication)
                short keySetLen = mFiraClientContext.getKeySet(mContext.mBuf[O_P2] == 0
                        ? sc1TagNumber : mContext.mBuf[O_P2], sInData, IN_DATA_KEYSET_OFFSET);
                short macKeyOffset = ClientContext.getKeyOffet(SC1_KEYSET, MAC_KEYTYPE,
                        sInData, IN_DATA_KEYSET_OFFSET, keySetLen);
                short encKeyOffset = ClientContext.getKeyOffet(SC1_KEYSET, ENC_KEYTYPE,
                        sInData, IN_DATA_KEYSET_OFFSET, keySetLen);

                if (sCrypto.verifyCmacAes128(sInData, macKeyOffset, SIGNATURE_BLOCK_SIZE,
                        buffer, index, (short) (cryptoICCLen - SIGNATURE_BLOCK_SIZE),
                        buffer, (short) (index + cryptoICCLen - SIGNATURE_BLOCK_SIZE),
                        SIGNATURE_BLOCK_SIZE)) {

                    // IV calculation
                    short outLen = sCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, sInData,
                            macKeyOffset, Scp3Lib.mNullBytes16, (short) 0, SIGNATURE_BLOCK_SIZE,
                            mContext.mBuf, O_RANDOM_ICC, BlOCK_16BYTES, sOutData, (short) 0);

                    short inLen = sCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, sInData,
                            encKeyOffset, sOutData, (short) 0, outLen, buffer, index,
                            (short) (cryptoICCLen - SIGNATURE_BLOCK_SIZE), sInData, (short) 0);

                    if ((inLen > 32) && 0 == Util.arrayCompare(sInData, (short) 0, mContext.mBuf,
                            O_RANDOM_ICC, SIGNATURE_BLOCK_SIZE) &&
                            0 == Util.arrayCompare(sInData, SIGNATURE_BLOCK_SIZE, mContext.mBuf,
                                    O_RANDOM_IFD, SIGNATURE_BLOCK_SIZE)) {
                        // now sInData has "RND.ICC ║ RND.IFD ║ K.ICC ║ SI ║ [Text2] ║ Padding"
                        // concatenate "KIFD + KICC"
                        Util.arrayCopyNonAtomic(mContext.mBuf, O_KIFD, sInData, SIGNATURE_BLOCK_SIZE,
                                BlOCK_16BYTES);
                        Util.arrayFillNonAtomic(sInData, (short) (SIGNATURE_BLOCK_SIZE * 3),
                                (short) 15, C_00);
                        sInData[(short) ((SIGNATURE_BLOCK_SIZE * 3) + 14)] = T_80;
                        // 7.2.1.4.2 Derivation of the Secure Messaging Session Keys
                        // KSENC = PRF(KENC, 0x00000000000000000000000400008001 ║ K.IFD ║ K.ICC)
                        // KSMAC = PRF(KMAC, 0x00000000000000000000000600008001 ║ K.IFD ║ K.ICC)
                        mCommon.setScpAndUWBsessionKey(sInData, (short) (SIGNATURE_BLOCK_SIZE * 3),
                                sInData, SIGNATURE_BLOCK_SIZE, (short) (SIGNATURE_BLOCK_SIZE * 2),
                                sInData, encKeyOffset, macKeyOffset, sOutData, (short) 0);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean verifySelectADFResponseSC2(byte[] buffer, short bufferOffset) {

        short index = bufferOffset;

        if (buffer[index++] == T_6F) {

            index += BerTlvParser.getTotalLengthBytesCount(buffer, index);

            if (buffer[index] == T_85) {
                index += 2;
                Util.arrayCopyNonAtomic(buffer, index, mContext.mBuf, O_RANDOM_DATA0, BlOCK_16BYTES);

                short keySetLen = mFiraClientContext.getKeySet(mContext.mBuf[O_P2], sInData,
                        IN_DATA_KEYSET_OFFSET);
                short macKeyOffset = ClientContext.getKeyOffet(SC2_PRIVACY_KEYSET, MAC_KEYTYPE,
                        sInData, IN_DATA_KEYSET_OFFSET, keySetLen);
                short cryptoLen = sCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, sInData,
                        macKeyOffset, mContext.mBuf, O_RANDOM_DATA0, SIGNATURE_BLOCK_SIZE, buffer,
                        (short) (index + SIGNATURE_BLOCK_SIZE), SIGNATURE_BLOCK_SIZE, sOutData,
                        (short) 0);

                cryptoLen = Crypto.unpadM2(sOutData, (short) 0, cryptoLen);

                if (sOutData[0] == C_00) {
                    mContext.mBuf[O_SELECTION_INDEX] = sOutData[1];
                    Util.arrayCopyNonAtomic(sOutData, (short) 2, mContext.mBuf, O_DEVICE_IDENTIFIER,
                            DEVICE_IDENTIFIER_SIZE);
                    return true;
                }

            } else if (buffer[index] == T_81) {
                Util.arrayCopyNonAtomic(buffer, (short) (index + 2), mContext.mBuf,
                        O_EPHEMERAL_PUBKEY2, (short) buffer[(short) (index + 1)]);
                return true;
            } else if (buffer[index++] == T_84) {

                short len84 = BerTlvParser.getDataLength(buffer, index);

                index += BerTlvParser.getTotalLengthBytesCount(buffer, index);
                Util.arrayCopyNonAtomic(buffer, index, mContext.mBuf, O_SELECTED_OID, len84);
                index += len84;

                if (buffer[index++] == T_86) {
                    // this has to be 13 bytes
                    short len86 = BerTlvParser.getDataLength(buffer, index);
                    index += BerTlvParser.getTotalLengthBytesCount(buffer, index);
                    Util.arrayCopyNonAtomic(buffer, index, mContext.mBuf, O_DEVICE_IDENTIFIER,
                            len86);
                    return true;
                }
            }
        }
        return false;
    }

    private boolean verifyGA1SymmetricResponseSC2(byte[] buffer, short bufferOffset) {

        short index = bufferOffset;

        if (buffer[index++] == T_7C && buffer[index++] == T_2F && buffer[index++] == T_82
                && buffer[index++] == T_2D) {

            index += 11;

            if (buffer[index++] == (byte) 0x03 && buffer[index++] == T_70) {
                index = Util.arrayCopyNonAtomic(buffer, index, mContext.mBuf, O_CHALLENGE2,
                        BlOCK_16BYTES);
                // NOTE: to check Cryptogram2
                return true;
            }
        }
        return false;
    }

    private boolean verifyGAAsymmetricCmdSC2(byte[] buffer, short bufferOffset) {

        short index = bufferOffset;

        if (buffer[index++] == T_7C) {
            index += BerTlvParser.getTotalLengthBytesCount(buffer, index);

            if (buffer[index++] == T_82) {
                short len82 = BerTlvParser.getDataLength(buffer, index);
                index += BerTlvParser.getTotalLengthBytesCount(buffer, index);

                short msg2EncLen = sCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT,
                        mContext.mBuf, O_KSES_AUTHENC, Scp3Lib.mNullBytes16, (short) 0,
                        BlOCK_16BYTES, buffer, index, len82, sInData, (short) 0);

                msg2EncLen = Crypto.unpadM2(sInData, (short) 0, msg2EncLen);

                short msg2extLen = msg2EncLen;
                if (mContext.mBuf[O_AUTH_METHOD] == ASYM_MUTUAL ||
                        mContext.mBuf[O_AUTH_METHOD] == ASYM_MUTUAL_SEAMLESS) {
                    // Msg.2.ext = 0xE1E1 | OptsB | E.Pub.2 | E.Pub.1
                    sInData[msg2extLen++] = T_E1;
                    sInData[msg2extLen++] = T_E1;
                    sInData[msg2extLen++] = C_00;
                    Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY2, sInData,
                            msg2extLen, EC_PK_KEY_LENGTH);
                    msg2extLen += EC_PK_KEY_LENGTH;
                    Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY1, sInData,
                            msg2extLen, EC_PK_KEY_LENGTH);
                    msg2extLen += EC_PK_KEY_LENGTH;
                    msg2extLen -= msg2EncLen;

                    if (sCrypto.verifyECDSAPlainSignatureSha256(mContext.mBuf, O_KEY_PUB_ENC,
                            EC_PK_KEY_LENGTH, sInData, msg2EncLen, msg2extLen, sInData, (short) 1,
                            ECD_64BYTES_SIGNATURE)) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
        return false;
    }

    private short getUWBrootKeyBufferSet(byte[] buffer, short bufferOffset) {
         // Need to have generic function to retrieve the key set based on type and kvn
        return mFiraClientContext.getSelectedKvn(FiraClientContext.UWB_ROOT_KEY_SET, buffer,
                bufferOffset);
        /*
        short sc1TagNumber = Util.getShort(mContext.mBuf, O_SC1_TAGNUMBER);
        return mFiraClientContext.getKeySet(mContext.mBuf[O_P2] == 0 ?
                sc1TagNumber : mContext.mBuf[O_P2], buffer, bufferOffset);
        */
    }

    private short getUWBrootKeyOffset(byte[] buffer, short bufferOffset, short bufferLen) {
        return ClientContext.getTagValueOffset(UWB_ROOT_KEYTYPE, buffer, bufferOffset, bufferLen);
    }

    private short getLabelOffset(byte[] buffer, short bufferOffset, short bufferLen) {
        return ClientContext.getTagValueOffset(UWB_DERIVATION_LABEL, buffer, bufferOffset,
                bufferLen);
    }

    private short generateRDSbuffer(byte[] output, short outputOffset, short outputLength,
            byte[] uwbSessionKey, short uwbSessionKeyOffset, short uwbSessionKeyLength,
            byte[] uwbSessionID, short uwbSessionIDoffset, boolean multiCast) {

        short rdsFlag = Util.getShort(mContext.mBuf, O_RDS_FLAG);
        short offset = outputOffset;
        {
             offset = BerTlvBuilder.addTlv(output, offset, outputLength, T_C0, uwbSessionKey,
                     uwbSessionKeyOffset, uwbSessionKeyLength);

             // 0xC1 16or32 Responder-specific Sub-session key
             if (multiCast) {
                 // 9.2.2.9.5 UWB Responder Specific Sub-session Key Derivation
                 // (TBD / refer to section 8) TODO: change the value buffer after integration
                 offset = BerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC1, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xC2 2 Proximity Distance
             if ((rdsFlag & (short) 0x04) == (short) 0x04) {
                 // change the value buffer after integration
                 offset = BerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC2, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xC3 2 Angle of Arrival (AoA)
             if ((rdsFlag & (short) 0x08) == (short) 0x08) {
                 // change the value buffer after integration
                 offset = BerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC3, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xC4 1-128 Client specific data
             if ((rdsFlag & (short) 0x10) == (short) 0x10) {
                 // change the value buffer after integration
                 offset = BerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC4, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xC6 var. Key Exchange Key Identifier
             if ((rdsFlag & (short) 0x40) == (short) 0x40) {
                 // change the value buffer after integration
                 offset = BerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC6, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xCE 5-16 Service Applet AID
             if ((rdsFlag & (short) 0x0200) == (short) 0x0200) {
                 // change the value buffer after integration
                 offset = BerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xCE, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             offset = BerTlvBuilder.addTlv(output, offset, outputLength,
                     T_CF, uwbSessionID, uwbSessionIDoffset, UWB_SESSION_ID_SIZE);
        }

        return (short) (offset - outputOffset);
    }

    private boolean verifyResponse(byte[] buffer, short bufferOffset, short bufferLength) {

        // First check Status
        if (Util.getShort(buffer, (short) (bufferOffset + bufferLength - 2))
                == APDU_SUCCESS /*(0x9000)*/) {
            // verify response based on SCP_STATUS
            switch (mContext.mBuf[O_SCP_STATUS]) {
                case SC_SELECT_NO_CONNECTION:
                    return verifySelect(buffer, bufferOffset);
                case SC1_SELECT_ADF:
                    return verifySelectADFResponseSC1(buffer, bufferOffset);
                case SC2_SELECT_ADF_SYS:
                    return verifySelectADFResponseSC2(buffer, bufferOffset);
                case SC2_SELECT_ADF_ASYS:
                    return verifySelectADFResponseSC2(buffer, bufferOffset);
                case SC1_GA1:
                    return verifyGA1ResponseSC1(buffer, bufferOffset);
                case SC2_GA1:
                    return verifyGA1SymmetricResponseSC2(buffer, bufferOffset);
                case SC1_GA2:
                    return verifyGA2ResponseSC1(buffer, bufferOffset);
                case SC2_GA2:
                    return true;
                case SC2_GA:
                    return verifyGAAsymmetricCmdSC2(buffer, bufferOffset);
            }
        }

        return false;
    }

    //-----------------------------Public Functions-----------------------------
    /**
     * Handle incoming protocol object which process following commands "SELECT", "SELECT_ADF" and
     * "GENERAL_AUTHENTICATE" when device act as a responder or which process initiator side 
     * code (generating select_adf/GA command and verifying their responses) for FiRa secure channel
     *
     *  NOTE:- 'buff' needs to have sufficient memory to handle all protocol data
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     * 
     * @return In case of responder, return a length of individual response(SELECT_ADF &
     *         GENERAL_AUTHENTICATE) stored in "buff" from "buffOffset" or in case of initiator,
     *         return a length of generated commands (SELECT_ADF & GENERAL_AUTHENTICATE)
     */
    public short handleProtocolObject(byte[] buff, short buffOffset, short buffLen) {

        short retLen = 0;

        if (mContext.isInitiator()) {
            if (!verifyResponse(buff, buffOffset, buffLen))
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);

            switch (mContext.mBuf[O_SCP_STATUS]) {
                case SC1_SELECT_ADF:
                case SC2_SELECT_ADF_SYS:
                    retLen = mInitiator.getGA(buff, buffOffset, Util.getShort(mContext.mBuf,
                            O_SC_KVN), (byte) 0x02, NONE);
                    break;
                case SC2_SELECT_ADF_ASYS:
                    retLen = mInitiator.getGA(buff, buffOffset, NONE /* SC kvn */, (byte) 0x02,
                            mContext.mBuf[O_SECURITY_LEVEL]);
                    break;
                case SC1_GA1:
                case SC2_GA1:
                    retLen = mInitiator.getGA(buff, buffOffset, Util.getShort(mContext.mBuf,
                            O_SC_KVN), (short) 0x02, mContext.mBuf[O_SECURITY_LEVEL]);
                    break;
                case SC1_GA2:
                case SC2_GA2:
                case SC2_GA:
                    mContext.mBuf[O_SCP_STATUS] = CONNECTION_DONE;
                    mFiraClientContext.signal(FiraClientContext.EVENT_SECURE);
                    break;
                case SC_SELECT_NO_CONNECTION:
                    // NOTE : SE do not need to select adf in initiator because it is selected
                    // before INIT TRANSACTION is called.
                    // The assumption for SC2 Asymmetric case is that there will be no privacy
                    // and the response will be similar to SC2 symmteric i.e. 0x84 tag will have
                    // selected OIDs.

                    // First: find out that privacy is supported
                    short len = mFiraClientContext.getSelectedKvn(FiraClientContext.PRIVACY_KEY_SET,
                            sInData, IN_DATA_KEYSET_OFFSET); // 0
                    short privKvn = getKvn(sInData, IN_DATA_KEYSET_OFFSET, len);
                    if (privKvn == INVALID_VALUE) {
                        privKvn = 0;
                    }
                    Util.setShort(mContext.mBuf, O_PRIV_KVN, privKvn);

                    // Second: find out scKvn and type of key set.
                    len = mFiraClientContext.getSelectedKvn(FiraClientContext.SC_KEY_SET, sInData,
                            IN_DATA_KEYSET_OFFSET);
                    short scKvn = getKvn(sInData, IN_DATA_KEYSET_OFFSET, len);
                    if (scKvn == INVALID_VALUE) {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    }
                    Util.setShort(mContext.mBuf, O_SC_KVN, scKvn);

                    // Finally, get the secure channel id
                    short secureChannelIdentifierOffset = ClientContext.getTagValueOffset(
                            SECURE_CHANNEL_IDENTIFIER, sInData, IN_DATA_KEYSET_OFFSET, len);
                    short scIdentifier = sInData[secureChannelIdentifierOffset];

                    // Get and assign Auth & security level
                    mContext.mBuf[O_AUTH_METHOD] = (sInData[IN_DATA_KEYSET_OFFSET] ==
                            TAG_ASYMMETRIC_KEY_SET)? ASYM_MUTUAL : SYM;
                    mContext.mBuf[O_SECURITY_LEVEL] = CDECMAC_RENCMAC;

                    //If SC2 and ASYM_MUTUAL then no privacy.
                    if (scIdentifier == SC2_KEYSET &&
                        mContext.mBuf[O_AUTH_METHOD] == ASYM_MUTUAL) {
                        retLen = mInitiator.getSelectADFCmdSC2(buff, buffOffset, mContext.mBuf,
                                O_SELECTED_OID, mContext.mBuf[O_SELECTED_OID_LEN], (byte) scKvn,
                                mContext.mBuf[O_AUTH_METHOD]);
                    } else {
                        if (scIdentifier == SC1_KEYSET) {
                            retLen = mInitiator.getSelectADFCmdSC1(buff, buffOffset, mContext.mBuf,
                                    O_SELECTED_OID, mContext.mBuf[O_SELECTED_OID_LEN], privKvn);
                        } else {
                            retLen = mInitiator.getSelectADFCmdSC2(buff, buffOffset, mContext.mBuf,
                                    O_SELECTED_OID, mContext.mBuf[O_SELECTED_OID_LEN],
                                    (byte) privKvn, mContext.mBuf[O_AUTH_METHOD]);
                        }
                    }
                    break;
            }
        } else {

            short cDataOffset = (short) (buff[(short) (buffOffset + ISO7816.OFFSET_LC)] == 0 ? 7 : 5);

            try {
                switch (mContext.mBuf[O_SCP_STATUS]) {
                    case SC1_SELECT_ADF:
                    case SC2_SELECT_ADF_SYS:
                    case SC2_SELECT_ADF_ASYS:
                    case SC1_GA1:
                    case SC2_GA1:
                        retLen = mResponder.processGeneralAuthentication(buff, buffOffset, buffLen,
                                cDataOffset);
    
                        // there is no ACK from initiator so making a status as CONNECTION_DONE
                        // once we set SCP_STATUS as SC1_GA2/SC2_GA2/SC2_GA
                        if (mContext.mBuf[O_SCP_STATUS] == SC1_GA2 || 
                            mContext.mBuf[O_SCP_STATUS] == SC2_GA2 ||
                            mContext.mBuf[O_SCP_STATUS] == SC2_GA) {
                            mContext.mBuf[O_SCP_STATUS] = CONNECTION_DONE;
                            mFiraClientContext.signal(FiraClientContext.EVENT_SECURE);
                        }
                        break;
                    case SC_SELECT_NO_CONNECTION:
                        retLen =  mResponder.parseSelectAdf(buff, buffOffset, buffLen, cDataOffset);
                        mFiraClientContext.signal(FiraClientContext.EVENT_OID);
                        break;
                }
            } catch (ISOException ex){
                retLen = (short) (Util.setShort(buff, buffOffset, ex.getReason()) - buffOffset);
            }
        }
        return retLen;
    }

    /**
     * Initiate FiRa SC using select command
     * This function generates select command, furthermore it takes OID as an argument
     * for subsequent commands 
     *
     * @param aidBuff : Applet AID buffer
     * @param aidBuffOffset : Applet AID's buffer offset
     * @param aidBuffLength : length of applet AID
     * @param oidData : OID buffer
     * @param oidDataOffset : OID buffer's offset
     * @param oidDataLength : OID length
     * @param buffer : output buffer
     * @param bufferOffset : output buffer offset
     * @param bufferLength : output buffer length
     *
     * @return length of generated select command
     */
    public short initiate(byte[] aidBuff, short aidBuffOffset, short aidBuffLength,
            byte[] oidData, short oidDataOffset, short oidDataLength, byte[] buffer,
            short bufferOffset, short bufferLength) {

        // TODO: buff can have multiple oid tags
        // addOids(oidData, oidDataOffset, oidDataLength);
        // Now Assuming only single OID is to be searched(validated from initiator side) MAX 32
        if (oidDataLength > MAX_OID_SIZE) {
            return 0;
        }

        Util.arrayCopyNonAtomic(oidData, oidDataOffset, mContext.mBuf, O_SELECTED_OID,
                oidDataLength);
        mContext.mBuf[O_SELECTED_OID_LEN] = (byte) oidDataLength;

        mContext.setRole(FiraConstant.INITIATOR);
        mContext.setState(FiraConstant.UNSECURE);
        mContext.mBuf[O_SCP_STATUS] = SC_SELECT_NO_CONNECTION;

        return getSelect(buffer, bufferOffset, aidBuff, aidBuffOffset, aidBuffLength);
    }

    public byte getSCPstatus() {
        return mContext.mBuf[O_SCP_STATUS];
    }

    /**
     * Get current protocol type which is fiRa 'SC1' or 'SC2'
     *
     * @return current protocol type.
     */
    public byte getProtocolType() {
        return 0;
    }

    /**
     *
     */
    public short getEventData(byte eventId, byte[] buf, short index) {
        switch (eventId) {
            case FiraClientContext.EVENT_OID:
                Util.arrayCopyNonAtomic(mContext.mBuf, O_SELECTED_OID,
                        buf, index,mContext.mBuf[O_SELECTED_OID_LEN]);
                return mContext.mBuf[O_SELECTED_OID_LEN];
            case FiraClientContext.EVENT_RDS:
                Util.arrayCopyNonAtomic(mContext.mBuf, O_UWB_SESSIONID,
                    buf, index, UWB_SESSION_ID_SIZE);
                return UWB_SESSION_ID_SIZE;
        }
        return 0;
    }

    /**
     * Terminate the ongoing session
     */
    public void terminate() {
        reset();
    }

    /**
     * Wrap(encrypt) incoming 'buff' start from 'buffOffset' based on assigned
     * 'mSecurityLevel' having length 'buffLen'
     *
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     *
     * @return length of wrapped data in 'buff' starting from 'buffOffset'
     */
    public short wrap(byte[] buff, short buffOffset, short buffLen)
            throws ArrayIndexOutOfBoundsException, ISOException {
        return mScp3Lib.wrap(mContext.mBuf[O_SECURITY_LEVEL], buff, buffOffset, buffLen,
                !mContext.isInitiator());
    }

    /**
     * Unwrap(decrypt) incoming 'buff' start from 'buffOffset' based on assigned
     * 'mSecurityLevel' having length 'buffLen'
     *
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     *
     * @return length of unwrapped data in 'buff' starting from 'buffOffset'
     */
    public short unwrap(byte[] buff, short buffOffset, short buffLen)
            throws ISOException {
        return mScp3Lib.unwrap(mContext.mBuf[O_SECURITY_LEVEL], buff, buffOffset, buffLen,
                mContext.isInitiator());
    }

    /**
     * Generate RDS data and store the RDS in 'output' starting form 'outputOffset'
     *
     * @param output : array to store RDS
     * @param outputOffset : start index of 'output' array
     * @param outputLength : max output length
     * @param sessionKeyInfo : UWB session info buffer
     * @param sessionKeyInfoOffset : UWB session info buffer's offset
     * @param sessionKeyInfoLen : UWB session info length
     * @param useSessionKeyInfo : UWB session key derivation scheme, true when 3 bit is set else
     *                            false 
     * @param useAsDiversificationData : 
     * @param uwbSessionSessionId : In case of uni-cast(non multi-cast) this is a UWB session id
     *                              buffer else null 
     *        **ASSUMPTION** = if session id is null means this is a multi-cast session and we have
     *         to generate session sub-key and session sub-id
     * @param uwbSessionSessionIdOffset : offset of uwbSessionOrSubSessionID
     *
     * @return length of RDS data store in 'output' from 'outputOffset'
     */
    public short generateRds(byte[] output, short outputOffset, short outputLength,
            byte[] sessionKeyInfo, short sessionKeyInfoOffset, short sessionKeyInfoLen,
            boolean useSessionKeyInfo, boolean useAsDiversificationData, byte[] uwbSessionSessionId,
            short uwbSessionSessionIdOffset) {

        short uwbSessionKeyLength = 0;

        // UWB Session Key Derivation Scheme
        // 0xx: derive UWB Session Key from the SC Session Keys
        //      if useSessionKeyInfo is false
        // 100: use value of UWB_SESSION_KEY_INFO directly as UWB Session Key
        //      if useSessionKeyInfo is true and useAsDiversificationData is false
        // 101: use value of UWB_SESSION_KEY_INFO as diversification data
        //      if both useSessionKeyInfo and useAsDiversificationData are true

        // NOTE:- Accumulate uwbsesseionid and uwbsessionkey in 'mInput' at/from 'UWB_DATA_OFFSET'
        if (useSessionKeyInfo) {
            if (useAsDiversificationData) {
                // “use value of UWB_SESSION_KEY_INFO as derivation data
                short uwbRootKeySetLength = getUWBrootKeyBufferSet(sInData, (short) 0);
                short uwbRootKeyOffset = getUWBrootKeyOffset(sInData, (short) 0,
                        uwbRootKeySetLength);
                short uwbLabelOffset = getLabelOffset(sInData, (short) 0, uwbRootKeySetLength);

                uwbSessionKeyLength = sCrypto.cmacKdfCounterModeUWBsessionKey(sInData,
                        uwbRootKeyOffset, sInData[(short) (uwbRootKeyOffset - 1)] /*length offset = value offset - 1*/,
                        sInData, uwbLabelOffset, UWB_DERIVATION_LABEL_SIZE, sessionKeyInfo,
                        sessionKeyInfoOffset, sessionKeyInfoLen, sInData, UWB_DATA_OFFSET);
            } else {
                // “use value of UWB_SESSION_KEY_INFO directly as UWB Session Key
                uwbSessionKeyLength = (short) (Util.arrayCopyNonAtomic(sessionKeyInfo,
                        sessionKeyInfoOffset, sInData, UWB_DATA_OFFSET, sessionKeyInfoLen)
                        - UWB_DATA_OFFSET);
            }
        } else {
            // derive UWB Session Key from the SC Session Keys (UWB default)
            uwbSessionKeyLength = (short) (Util.arrayCopyNonAtomic(mContext.mBuf, O_UWB_SESSIONKEY,
                    sInData, UWB_DATA_OFFSET, BlOCK_16BYTES) - UWB_DATA_OFFSET);
        }

        if (uwbSessionSessionId == null) {
            // if uwbSessionSessionId is null then it's a multi-cast operation; generate
            // SUB_SESSION_ID **ASSUMPTION** As per section '8.5.3.3.1' CSML v1.0.0-IPR 
            // A controller may use a default UWB Session Key and UWB Session ID if desired.
            Util.arrayCopyNonAtomic(mContext.mBuf, O_UWB_SESSIONID, sInData,
                     (short) (uwbSessionKeyLength + UWB_DATA_OFFSET), UWB_SESSION_ID_SIZE);
        } else {
            Util.arrayCopyNonAtomic(uwbSessionSessionId, uwbSessionSessionIdOffset, sInData,
                    (short) (uwbSessionKeyLength + UWB_DATA_OFFSET), UWB_SESSION_ID_SIZE);
        }

        short ret = generateRDSbuffer(output, outputOffset, outputLength, sInData, UWB_DATA_OFFSET,
                uwbSessionKeyLength, sInData, (short) (uwbSessionKeyLength + UWB_DATA_OFFSET),
                uwbSessionSessionId != null);
        // Signal RDS generated Event
        mFiraClientContext.signal(FiraClientContext.EVENT_RDS);
        return ret;
    }

    public void reset() {
        mContext.resetContext();
        Util.arrayFillNonAtomic(sInData,(short) 0, IN_DATA_SIZE, (byte) 0);
        Util.arrayFillNonAtomic(sOutData,(short) 0, OUT_DATA_SIZE,(byte) 0);
        mContext.mBuf[O_SCP_STATUS] = SC_SELECT_NO_CONNECTION;
        resetSecurity();
    }

    /**
     * reset the current security level to 'NO_SECURITY_LEVEL'
     */
    public void resetSecurity() {
        mContext.mBuf[O_SECURITY_LEVEL] = NO_SECURITY_LEVEL;
    }

    /**
     * Get current security level
     *
     * @return current security level
     */
    public byte getSecurityLevel() {
        return mContext.mBuf[O_SECURITY_LEVEL];
    }
}
