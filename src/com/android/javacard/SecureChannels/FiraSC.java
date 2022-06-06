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

    private KeyPair mEcKeyPair;
    private BerTlvBuilder mBerTlvBuilder;

    private Crypto mCrypto;
    private Scp3Lib mScp3Lib;
    private Certificates mCertificates;
    private FiraClientContext mFiraClientContext;
    private FiraContext mContext;

    private byte[] mInData;
    private byte[] mOutData;

    private FiraCommon mCommon;
    private FiraInitiator mInitiator;
    private FiraResponder mResponder;

    public FiraSC(FiraClientContext clientContext) {
        mEcKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        mBerTlvBuilder = new BerTlvBuilder();

        mCrypto = new Crypto();
        mScp3Lib = new Scp3Lib(mCrypto);
        mCertificates = new Certificates();
        Crypto.initECKey(mEcKeyPair);
        mFiraClientContext = clientContext;
        mContext = new FiraContext();

        mInData = JCSystem.makeTransientByteArray((short) IN_DATA_SIZE, JCSystem.CLEAR_ON_RESET);
        mOutData = JCSystem.makeTransientByteArray((short) OUT_DATA_SIZE, JCSystem.CLEAR_ON_RESET);

        // Create devices
        mCommon = new FiraCommon(mContext, mCrypto, mScp3Lib);
        mInitiator = new FiraInitiator(mContext, mFiraClientContext, mCrypto, mEcKeyPair,
                mScp3Lib, mCommon, mInData, mOutData);
        mResponder = new FiraResponder(mContext, mFiraClientContext, mCrypto, mEcKeyPair,
                mScp3Lib, mCertificates, mBerTlvBuilder, mCommon, mInData, mOutData);
    }

    private short getKvn(byte[] buf, short bufOffset, short bufLen) {
        if (bufLen > 0) {
            short kvnOffset = ClientContext.getTagValueOffset((byte) TAG_KVN, buf, bufOffset, bufLen);
            if (kvnOffset != INVALID_VALUE) {
                return buf[kvnOffset];
            }
        }
        return INVALID_VALUE;
    }

    // get Select
    private short getSelect(byte[] buffer, short bufferOffset, byte[] aidBuff, short aidBuffOffset, short aidBuffLength) {

        short index = bufferOffset;

        // CLA/INS/P1P2
        buffer[index++] = C_00;
        buffer[index++] = INS_SELECT;
        buffer[index++] = C_04;
        buffer[index++] = C_00;

        buffer[index++] = C_00; // Extended APDU
        index = Util.setShort(buffer, index, aidBuffLength);

        return (short) (Util.arrayCopyNonAtomic(aidBuff, aidBuffOffset, buffer, index, aidBuffLength)
                - bufferOffset);
    }

    private boolean verifySelect(byte[] buffer, short bufferOffset) {
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

        Util.arrayCopyNonAtomic(buffer, index, mContext.mContextBuffer, RANDOM_ICC_OFFSET, BlOCK_16BYTES);
        return true;
    }

    private boolean verifyGA2ResponseSC1(byte[] buffer, short bufferOffset) {

        short index = bufferOffset;
        short cryptoICCLen = 0;
        short sc1TagNumber = Util.getShort(mContext.mContextBuffer, SC1_TAGNUMBER_OFFSET);

        if (buffer[index++] == T_7C) {

            index += BerTlvParser.getTotalLengthBytesCount(buffer, index);

            if (buffer[index++] == T_82) {

                cryptoICCLen = BerTlvParser.getDataLength(buffer, index);
                index += BerTlvParser.getTotalLengthBytesCount(buffer, index);

                // Note: The Secure Messaging Authentication Key consists of KENC (used for encryption) and
                // KMAC(used for authentication)
                short keySetLen = mFiraClientContext.getKeySet(mContext.mContextBuffer[P2_OFFSET] == 0
                        ? sc1TagNumber : mContext.mContextBuffer[P2_OFFSET], mInData, IN_DATA_KEYSET_OFFSET);
                short macKeyOffset = ClientContext.getKeyOffet(SC1_KEYSET, MAC_KEYTYPE,
                        mInData, IN_DATA_KEYSET_OFFSET, keySetLen);
                short encKeyOffset = ClientContext.getKeyOffet(SC1_KEYSET, ENC_KEYTYPE,
                        mInData, IN_DATA_KEYSET_OFFSET, keySetLen);

                if (mCrypto.verifyCmacAes128(mInData, macKeyOffset, SIGNATURE_BLOCK_SIZE,
                        buffer, index, (short) (cryptoICCLen - SIGNATURE_BLOCK_SIZE),
                        buffer, (short) (index + cryptoICCLen - SIGNATURE_BLOCK_SIZE), SIGNATURE_BLOCK_SIZE)) {

                    // IV calculation
                    short outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mInData, macKeyOffset,
                            mScp3Lib.mNullBytes16, (short) 0, SIGNATURE_BLOCK_SIZE, mContext.mContextBuffer,
                            RANDOM_ICC_OFFSET, BlOCK_16BYTES, mOutData, (short) 0);

                    short inLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, mInData, encKeyOffset, mOutData,
                            (short) 0, outLen, buffer, index, (short) (cryptoICCLen - SIGNATURE_BLOCK_SIZE), mInData, (short) 0);

                    if ((inLen > 32) && 0 == Util.arrayCompare(mInData, (short) 0, mContext.mContextBuffer,
                            RANDOM_ICC_OFFSET, SIGNATURE_BLOCK_SIZE) &&
                            0 == Util.arrayCompare(mInData, SIGNATURE_BLOCK_SIZE, mContext.mContextBuffer,
                                    RANDOM_IFD_OFFSET, SIGNATURE_BLOCK_SIZE)) {
                        // now mInData has "RND.ICC ║ RND.IFD ║ K.ICC ║ SI ║ [Text2] ║ Padding"
                        // concatenate "KIFD + KICC"
                        Util.arrayCopyNonAtomic(mContext.mContextBuffer, KIFD_OFFSET, mInData, SIGNATURE_BLOCK_SIZE,
                                BlOCK_16BYTES);
                        Util.arrayFillNonAtomic(mInData, (short) (SIGNATURE_BLOCK_SIZE * 3), (short) 15, C_00);
                        mInData[(short) ((SIGNATURE_BLOCK_SIZE * 3) + 15)] = T_80;
                        // 7.2.1.4.2 Derivation of the Secure Messaging Session Keys
                        // KSENC = PRF(KENC, 0x00000000000000000000000400008001 ║ K.IFD ║ K.ICC)
                        // KSMAC = PRF(KMAC, 0x00000000000000000000000600008001 ║ K.IFD ║ K.ICC)
                        mCommon.setScpAndUWBsessionKey(mInData, (short) (SIGNATURE_BLOCK_SIZE * 3), mInData,
                                SIGNATURE_BLOCK_SIZE, (short) (SIGNATURE_BLOCK_SIZE * 2), mInData,
                                encKeyOffset, macKeyOffset, mOutData, (short) 0);
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
                Util.arrayCopyNonAtomic(buffer, index, mContext.mContextBuffer, RANDOM_DATA0_OFFSET, BlOCK_16BYTES);

                short keySetLen = mFiraClientContext.getKeySet(mContext.mContextBuffer[P2_OFFSET],
                        mInData, IN_DATA_KEYSET_OFFSET);
                short macKeyOffset = ClientContext.getKeyOffet(SC2_PRIVACY_KEYSET,
                        MAC_KEYTYPE, mInData, IN_DATA_KEYSET_OFFSET, keySetLen);
                short cryptoLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, mInData, macKeyOffset,
                        mContext.mContextBuffer, RANDOM_DATA0_OFFSET, SIGNATURE_BLOCK_SIZE, buffer,
                        (short) (index + SIGNATURE_BLOCK_SIZE), SIGNATURE_BLOCK_SIZE, mOutData, (short) 0);

                cryptoLen = Crypto.unpadM2(mOutData, (short) 0, cryptoLen);

                if (mOutData[0] == C_00) {
                    mContext.mContextBuffer[SELECTION_INDEX_OFFSET] = mOutData[1];
                    Util.arrayCopyNonAtomic(mOutData, (short) 2, mContext.mContextBuffer, DEVICE_IDENTIFIER_OFFSET,
                            DEVICE_IDENTIFIER_SIZE);
                    return true;
                }

            } else if (buffer[index] == T_81) {

                // E.Pub.2 is of 65 bytes
                Util.arrayCopyNonAtomic(buffer, (short) (index + 2), mContext.mContextBuffer, EPHEMERAL_PUBKEY2_OFFSET,
                        (short) buffer[(short) (index + 1)]);
                return true;

            } else if (buffer[index++] == T_84) {

                short len84 = BerTlvParser.getDataLength(buffer, index);

                index += BerTlvParser.getTotalLengthBytesCount(buffer, index);
                Util.arrayCopyNonAtomic(buffer, index, mContext.mContextBuffer, SELECTED_OID_OFFSET, len84);
                index += len84;

                if (buffer[index++] == T_86) {
                    short len86 = BerTlvParser.getDataLength(buffer, index); // this has to be 13 bytes
                    index += BerTlvParser.getTotalLengthBytesCount(buffer, index);
                    Util.arrayCopyNonAtomic(buffer, index, mContext.mContextBuffer, DEVICE_IDENTIFIER_OFFSET, len86);
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
                index = Util.arrayCopyNonAtomic(buffer, index, mContext.mContextBuffer, CHALLENGE2_OFFSET, BlOCK_16BYTES);
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

                short msg2EncLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, mContext.mContextBuffer,
                        KSES_AUTHENC_OFFSET, mScp3Lib.mNullBytes16, (short) 0, BlOCK_16BYTES, buffer, index,
                        len82, mInData, (short) 0);

                msg2EncLen = Crypto.unpadM2(mInData, (short) 0, msg2EncLen);

                short msg2extLen = msg2EncLen;
                if (mContext.mContextBuffer[AUTHENTICATE_METHOD_OFFSET] == ASYM_MUTUAL ||
                        mContext.mContextBuffer[AUTHENTICATE_METHOD_OFFSET] == ASYM_MUTUAL_SEAMLESS) {
                    // Msg.2.ext = 0xE1E1 | OptsB | E.Pub.2 | E.Pub.1
                    mInData[msg2extLen++] = T_E1;
                    mInData[msg2extLen++] = T_E1;
                    mInData[msg2extLen++] = C_00;
                    Util.arrayCopyNonAtomic(mContext.mContextBuffer, EPHEMERAL_PUBKEY2_OFFSET, mInData,
                            msg2extLen, EC_PK_KEY_LENGTH);
                    msg2extLen += EC_PK_KEY_LENGTH;
                    Util.arrayCopyNonAtomic(mContext.mContextBuffer, EPHEMERAL_PUBKEY1_OFFSET, mInData,
                            msg2extLen, EC_PK_KEY_LENGTH);
                    msg2extLen += EC_PK_KEY_LENGTH;
                    msg2extLen -= msg2EncLen;
                    // mCrypto.addPaddingM2(mInData, (short) 0, msg2extIndex);

                    if (mCrypto.verifyECDSAPlainSignatureSha256(mContext.mContextBuffer, KEY_PUB_ENC_OFFSET,
                            EC_PK_KEY_LENGTH, mInData, msg2EncLen, msg2extLen, mInData, (short) 1, ECD_64BYTES_SIGNATURE)) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
        return false;
    }

    private short getAdfExtendedBytes(byte[] buffer, short bufferOffset) {
        return ClientContext.getAdfExtendedBytes(mContext.mContextBuffer, SELECTED_OID_OFFSET,
                mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET] ,buffer, bufferOffset);
    }

    private short getUWBsessionKeyInfoBuffer(byte[] buffer, short bufferOffset) {
        return ClientContext.getUWBsessionKeyInfoBuffer(mContext.mContextBuffer, SELECTED_OID_OFFSET,
                mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET] ,buffer, bufferOffset);
    }

    private short getUWBrootKeyBufferSet(byte[] buffer, short bufferOffset) {
        short sc1TagNumber = Util.getShort(mContext.mContextBuffer, SC1_TAGNUMBER_OFFSET);

        return mFiraClientContext.getKeySet(mContext.mContextBuffer[P2_OFFSET] == 0 ?
                sc1TagNumber : mContext.mContextBuffer[P2_OFFSET], buffer, bufferOffset);
    }

    private short getUWBrootKeyOffset(byte[] buffer, short bufferOffset, short bufferLen) {
        return ClientContext.getTagValueOffset(UWB_ROOT_KEYTYPE, buffer, bufferOffset, bufferLen);
    }

    private short getUWBsessionID(byte[] buffer, short bufferOffset) {
        return ClientContext.getSessionId(mContext.mContextBuffer, SELECTED_OID_OFFSET,
                mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET] ,buffer, bufferOffset);
    }

    private short getLabelBuffer(byte[] buffer, short bufferOffset) {
        return ClientContext.getLabel(mContext.mContextBuffer, SELECTED_OID_OFFSET,
                mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET] ,buffer, bufferOffset);
    }

    private short generateRDSbuffer(byte[] output, short outputOffset, short outputLength,
            byte[] uwbSessionKey, short uwbSessionKeyOffset, short uwbSessionKeyLength,
            byte[] uwbSessionID, short uwbSessionIDoffset) {

        short rdsFlag = Util.getShort(mContext.mContextBuffer, RDS_FLAG_OFFSET);
        short offset = outputOffset;
        {
             offset = mBerTlvBuilder.addTlv(output, offset, outputLength,
                                            T_C0, uwbSessionKey, uwbSessionKeyOffset, uwbSessionKeyLength);

             // 0xC1 16or32 Responder-specific Sub-session key
             if ((rdsFlag & (short) 0x02) == (short) 0x02) {
                 // TODO: change the value buffer after integration
                 offset = mBerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC1, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xC2 2 Proximity Distance
             if ((rdsFlag & (short) 0x04) == (short) 0x04) {
                 // TODO: change the value buffer after integration
                 offset = mBerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC2, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xC3 2 Angle of Arrival (AoA)
             if ((rdsFlag & (short) 0x08) == (short) 0x08) {
                 // TODO: change the value buffer after integration
                 offset = mBerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC3, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xC4 1-128 Client specific data
             if ((rdsFlag & (short) 0x10) == (short) 0x10) {
                 // TODO: change the value buffer after integration
                 offset = mBerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC4, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xC6 var. Key Exchange Key Identifier
             if ((rdsFlag & (short) 0x40) == (short) 0x40) {
                 // TODO: change the value buffer after integration
                 offset = mBerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xC6, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             // 0xCE 5-16 Service Applet AID
             if ((rdsFlag & (short) 0x0200) == (short) 0x0200) {
                 // TODO: change the value buffer after integration
                 offset = mBerTlvBuilder.addTlv(output, offset, outputLength,
                         (byte) 0xCE, uwbSessionID, uwbSessionIDoffset,
                         (short) 4);
             }

             offset = mBerTlvBuilder.addTlv(output, offset, outputLength,
                     T_CF, uwbSessionID, uwbSessionIDoffset, UWB_SESSION_ID_SIZE);
        }

        return (short) (offset - outputOffset);
    }

    private boolean verifyResponse(byte[] buffer, short bufferOffset) {

        switch (mContext.mContextBuffer[SCP_STATUS_OFFSET]) {
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

        return false;
    }

    ///////////////////////////////Public Functions//////////////////////////////////
    /**
     * Handle incoming protocol object which process following commands "SELECT", "SELECT_ADF" and
     * "GENERAL_AUTHENTICATE" when device act as a responder or which process initiator side 
     * code (generating select_adf/GA command and verifying their responses) for FiRa secure channel
     *
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     * 
     * @return In case of responder, return a length of individual response(SELECT_ADF & GENERAL_AUTHENTICATE)
     *         stored in "buff" from "buffOffset" or in case of initiator, return a length of generated 
     *         commands (SELECT_ADF & GENERAL_AUTHENTICATE)
     */
    public short handleProtocolObject(byte[] buff, short buffOffset, short buffLen) {

        short retLen = 0;

        if (mContext.isInitiator()) {
            if (!verifyResponse(buff, buffOffset))
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);

            switch (mContext.mContextBuffer[SCP_STATUS_OFFSET]) {
                case SC1_SELECT_ADF:
                case SC2_SELECT_ADF_SYS:
                    retLen = mInitiator.getGA(buff, buffOffset, Util.getShort(mContext.mContextBuffer, SC_KVN_OFFSET) /* SC kvn */,
                            (byte) 0x02, NONE);
                    break;
                case SC2_SELECT_ADF_ASYS:
                    retLen = mInitiator.getGA(buff, buffOffset, NONE /* SC kvn */, (byte) 0x02,
                            mContext.mContextBuffer[SECURITY_LEVEL_OFFSET]);
                    break;

                case SC1_GA1:
                case SC2_GA1:
                    retLen = mInitiator.getGA(buff, buffOffset, Util.getShort(mContext.mContextBuffer, SC_KVN_OFFSET) /* SC kvn */,
                            (short) 0x02, mContext.mContextBuffer[SECURITY_LEVEL_OFFSET]);
                    break;

                case SC1_GA2:
                case SC2_GA2:
                case SC2_GA:
                    mContext.mContextBuffer[SCP_STATUS_OFFSET] = CONNECTION_DONE;
                    mFiraClientContext.signal(FiraClientContext.EVENT_SECURE);
                    break;

                case SC_SELECT_NO_CONNECTION:
                    // NOTE : SE do not need to select adf in initiator because it is selected
                    // before INIT TRANSACTION is called.
                    // The assumption for SC2 Asymmetric case is that there will be no privacy
                    // and the response will be similar to SC2 symmteric i.e. 0x84 tag will have
                    // selected OIDs.

                    // First: find out that privacy is supported
                    short len = mFiraClientContext.getSelectedKvn(FiraClientContext.PRIVACY_KEY_SET, mInData,
                            IN_DATA_KEYSET_OFFSET); // 0
                    short privKvn = getKvn(mInData, IN_DATA_KEYSET_OFFSET, len);
                    if (privKvn == INVALID_VALUE) {
                        privKvn = 0;
                    }
                    Util.setShort(mContext.mContextBuffer, PRIV_KVN_OFFSET, privKvn);

                    // Second: find out scKvn and type of key set.
                    len = mFiraClientContext.getSelectedKvn(FiraClientContext.SC_KEY_SET, mInData, IN_DATA_KEYSET_OFFSET);
                    short scKvn = getKvn(mInData, IN_DATA_KEYSET_OFFSET, len);
                    if (scKvn == INVALID_VALUE) {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    }
                    Util.setShort(mContext.mContextBuffer, SC_KVN_OFFSET, scKvn);

                    // Finally, get the secure channel id
                    short secureChannelIdentifierOffset = ClientContext.getTagValueOffset(SECURE_CHANNEL_IDENTIFIER,
                            mInData, IN_DATA_KEYSET_OFFSET, len);
                    short scIdentifier = mInData[secureChannelIdentifierOffset];

                    // Get and assign Auth & security level
                    mContext.mContextBuffer[AUTH_METHOD_OFFSET] =
                        (mInData[IN_DATA_KEYSET_OFFSET] == TAG_ASYMMETRIC_KEY_SET)? ASYM_MUTUAL : SYM;
                    mContext.mContextBuffer[SECURITY_LEVEL_OFFSET] = CDECMAC_RENCMAC;

                    //If SC2 and ASYM_MUTUAL then no privacy.
                    if (scIdentifier == SC2_KEYSET &&
                        mContext.mContextBuffer[AUTH_METHOD_OFFSET] == ASYM_MUTUAL) {
                        retLen = mInitiator.getSelectADFCmdSC2(buff, buffOffset, mContext.mContextBuffer, SELECTED_OID_OFFSET,
                            mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET], (byte) scKvn,
                            mContext.mContextBuffer[AUTH_METHOD_OFFSET]);
                    } else {
                        if (scIdentifier == SC1_KEYSET) {
                            retLen = mInitiator.getSelectADFCmdSC1(buff, buffOffset, mContext.mContextBuffer, SELECTED_OID_OFFSET,
                                mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET], privKvn);
                        } else {
                            retLen = mInitiator.getSelectADFCmdSC2(buff, buffOffset, mContext.mContextBuffer, SELECTED_OID_OFFSET,
                                mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET], (byte) privKvn,
                                mContext.mContextBuffer[AUTH_METHOD_OFFSET]);
                        }
                    }
                    break;
            }
        } else {

            short cDataOffset = (short) (buff[(short) (buffOffset + ISO7816.OFFSET_LC)] == 0 ? 7 : 5);

            switch (mContext.mContextBuffer[SCP_STATUS_OFFSET]) {
                case SC1_SELECT_ADF:
                case SC2_SELECT_ADF_SYS:
                case SC2_SELECT_ADF_ASYS:
                case SC1_GA1:
                case SC2_GA1:
                    retLen = mResponder.processGeneralAuthentication(buff, buffOffset, buffLen, cDataOffset);

                    // there is no ACK from initiator so making a status as CONNECTION_DONE 
                    // once we set SCP_STATUS as SC1_GA2/SC2_GA2/SC2_GA
                    if (mContext.mContextBuffer[SCP_STATUS_OFFSET] == SC1_GA2 || 
                        mContext.mContextBuffer[SCP_STATUS_OFFSET] == SC2_GA2 ||
                        mContext.mContextBuffer[SCP_STATUS_OFFSET] == SC2_GA) {
                        mContext.mContextBuffer[SCP_STATUS_OFFSET] = CONNECTION_DONE;
                        mFiraClientContext.signal(FiraClientContext.EVENT_SECURE);
                    }
                    break;
                case SC_SELECT_NO_CONNECTION:
                    retLen =  mResponder.parseSelectAdf(buff, buffOffset, buffLen, cDataOffset);
                    mFiraClientContext.signal(FiraClientContext.EVENT_OID);
                    break;
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

        Util.arrayCopyNonAtomic(oidData, oidDataOffset, mContext.mContextBuffer, SELECTED_OID_OFFSET, oidDataLength);
        mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET] = (byte) oidDataLength;

        mContext.setRole(FiraConstant.INITIATOR);
        mContext.setState(FiraConstant.UNSECURE);
        mContext.mContextBuffer[SCP_STATUS_OFFSET] = SC_SELECT_NO_CONNECTION;

        return getSelect(buffer, bufferOffset, aidBuff, aidBuffOffset, aidBuffLength);
    }

    public byte getSCPstatus() {
        return mContext.mContextBuffer[SCP_STATUS_OFFSET];
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
                Util.arrayCopyNonAtomic(mContext.mContextBuffer, SELECTED_OID_OFFSET,
                        buf, index,mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET]);
                return mContext.mContextBuffer[SELECTED_OID_LENGTH_OFFSET];
            case FiraClientContext.EVENT_RDS:
                Util.arrayCopyNonAtomic(mContext.mContextBuffer, UWB_SESSIONID_OFFSET,
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
        return mScp3Lib.wrap(mContext.mContextBuffer[SECURITY_LEVEL_OFFSET], buff, buffOffset, buffLen);
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
        return mScp3Lib.unwrap(mContext.mContextBuffer[SECURITY_LEVEL_OFFSET], buff, buffOffset, buffLen);
    }

    /**
     * Generate RDS data and store the RDS in 'output' starting form 'outputOffset'
     *
     * @param output : array to store RDS
     * @param outputOffset : start index of 'output' array
     * @param outputLength : max output length
     * @param sessionKeyInfo :
     * @param start :
     * @param len :
     * @param useSessionKeyInfo :
     * @param useAsDiversificationData :
     *
     * @return length of RDS data store in 'output' from 'outputOffset'
     */
    public short generateRds(byte[] output, short outputOffset, short outputLength,
        byte[] sessionKeyInfo, short start, short len,
        boolean useSessionKeyInfo, boolean useAsDiversificationData) {

        short uwbSessionKeyLength = 0;

        // Accumulate uwbsesseionid and uwbsessionkey in 'mInput'
        // Create Session Key
        if (useSessionKeyInfo) {

            short adfExtendedBytes = getAdfExtendedBytes(mInData, (short) 0);
            if (adfExtendedBytes < 0) {
                return 0;
            }

            byte adfExtendedByte2 = mInData[1];

            if ((adfExtendedByte2 & E_USE_UWB_INFO) == E_USE_UWB_INFO) {
                // “use value of UWB_SESSION_KEY_INFO directly as UWB Session Key
                uwbSessionKeyLength = getUWBsessionKeyInfoBuffer(mInData, UWB_DATA_OFFSET);
            } else if ((adfExtendedByte2 & E_USE_UWB_SESSION_INFO_AS_DIVERSIFICATION_DATA)
                    == E_USE_UWB_SESSION_INFO_AS_DIVERSIFICATION_DATA) {
                // “use value of UWB_SESSION_KEY_INFO as derivation data

                short uwbRootKeySetLength = getUWBrootKeyBufferSet(mInData, (short) 0);
                short uwbRootKeyOffset = getUWBrootKeyOffset(mInData, (short) 0, uwbRootKeySetLength);
                short uwbLabelLength = getLabelBuffer(mInData, uwbRootKeySetLength);
                short uwbSessionKeyInfoLength = getUWBsessionKeyInfoBuffer(mInData,
                        (short) (uwbRootKeySetLength + uwbLabelLength));

                uwbSessionKeyLength = mCrypto.cmacKdfCounterModeUWBsessionKey(mInData,
                        uwbRootKeyOffset, mInData[(short) (uwbRootKeyOffset - 1)] /*length offset = value offset - 1*/,
                        mInData, uwbRootKeySetLength, uwbLabelLength, mInData,
                        (short) (uwbRootKeySetLength + uwbLabelLength), uwbSessionKeyInfoLength,
                        mInData, UWB_DATA_OFFSET);

            } else if ((adfExtendedByte2 & E_DERIVE_FROM_SC_SESSION_KEY) == E_DERIVE_FROM_SC_SESSION_KEY) {
                // derive UWB Session Key from the SC Session Keys
                uwbSessionKeyLength = (short) (Util.arrayCopyNonAtomic(mContext.mContextBuffer, UWB_SESSIONKEY_OFFSET,
                        mInData, UWB_DATA_OFFSET, BlOCK_16BYTES) - UWB_DATA_OFFSET);
            } else {
                // RFU
                return 0;
            }

            getUWBsessionID(mInData, (short) (uwbSessionKeyLength + UWB_DATA_OFFSET));
        } else {
            uwbSessionKeyLength = (short) (Util.arrayCopyNonAtomic(mContext.mContextBuffer, UWB_SESSIONKEY_OFFSET,
                    mInData, UWB_DATA_OFFSET, BlOCK_16BYTES) - UWB_DATA_OFFSET);
            Util.arrayCopyNonAtomic(mContext.mContextBuffer, UWB_SESSIONID_OFFSET, mInData,
                    (short) (uwbSessionKeyLength + UWB_DATA_OFFSET), UWB_SESSION_ID_SIZE);
        }

        short ret = generateRDSbuffer(output, outputOffset, outputLength,
                mInData, UWB_DATA_OFFSET, uwbSessionKeyLength,
                mInData, (short) (uwbSessionKeyLength + UWB_DATA_OFFSET));
        mFiraClientContext.signal(FiraClientContext.EVENT_RDS);
        return ret;
    }

    public void reset() {
        mContext.resetContext();
        Util.arrayFillNonAtomic(mInData,(short)0, (short)mInData.length,(byte)0);
        Util.arrayFillNonAtomic(mOutData,(short)0, (short)mOutData.length,(byte)0);
        mContext.mContextBuffer[SCP_STATUS_OFFSET] = SC_SELECT_NO_CONNECTION;
        resetSecurity();
    }

    /**
     * reset the current security level to 'NO_SECURITY_LEVEL'
     */
    public void resetSecurity() {
        mContext.mContextBuffer[SECURITY_LEVEL_OFFSET] = NO_SECURITY_LEVEL;
    }

    /**
     * Get current security level
     *
     * @return current security level
     */
    public byte getSecurityLevel() {
        return mContext.mContextBuffer[SECURITY_LEVEL_OFFSET];
    }
}
