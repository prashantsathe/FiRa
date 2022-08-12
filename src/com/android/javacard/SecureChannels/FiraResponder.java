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
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class FiraResponder {

    private FiraContext mContext;
    private FiraClientContext mFiraClientContext;
    private Crypto mCrypto;
    private KeyPair mEcKeyPair;
    private Certificates mCertificates;
    private BerTlvBuilder mBerTlvBuilder;
    private Scp3Lib mScp3Lib;
    private FiraCommon mCommon;

    private byte[] mInData;
    private byte[] mOutData;

    public FiraResponder(FiraContext context, FiraClientContext firaClientContext, Crypto crypto,
            KeyPair ecKeyPair, Scp3Lib scp3Lib, Certificates certificates,
            BerTlvBuilder berTlvBuilder, FiraCommon common, byte[] inData, byte[] outData) {
        mContext = context;
        mFiraClientContext = firaClientContext;
        mCrypto = crypto;
        mEcKeyPair = ecKeyPair;
        mScp3Lib = scp3Lib;
        mCertificates = certificates;
        mBerTlvBuilder = berTlvBuilder;
        mCommon = common;
        mInData = inData;
        mOutData = outData;
    }

    private short generateMsg2(byte[] outBuff, short outBuffOffset, short outBuffLength,
            byte[] msg2Enc, short msg2EncOffset, short msg2EncLength) {

        short offset = outBuffOffset;
        {
            // mBerTlvBuilder.reset();
            mBerTlvBuilder.startCOTag(offset);
            {
                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength,
                                               RES_82, msg2Enc, msg2EncOffset,
                                               msg2EncLength);
            }
                offset = mBerTlvBuilder.endCOTag(outBuff, offset, RES_7C);
        }

        // Add 9000 success and return
        return (short) (Util.setShort(outBuff, offset, APDU_SUCCESS) - outBuffOffset);
    }

    private short getADF(byte[] buffer, short bufferOffset) {
        return ClientContext.getADFdata(mContext.mBuf, O_SELECTED_OID,
                mContext.mBuf[O_SELECTED_OID_LEN], buffer, bufferOffset);
    }

    // FiRa Device 2 shall generate a shared secret key ShS and derive KSesAuthEnc and KSCP03rootkey.
    // Note: the generation of KSCP03rootkey can be delayed until authentication is successful.
    // FiRa Device 2 shall decrypt Msg.1.enc, validate Cert.1 and shall then verify Sig.1. If any
    // of the steps is not successful, FiRa Device 2 shall return error. Note: it will be the
    // responsibility of the Service Provider to provision unambiguously ADF with a public key to
    // check certificate. 
    private short processAsymmetricSC2Authentication(byte[] dataBuff, short dataBuffOffset,
            short dataBuffLength, short cDataOffset, short msg7CByteCnt) {

        short outLen = 0, kdkLength = 0, kSesAuthEncLength = 0, kScp03RootLength = 0;
        short cDataBuffOffset = (short) (dataBuffOffset + cDataOffset);
        short cDataBuffLength = (short) (dataBuffLength - cDataOffset);
        short msg1EncLengthByteCnt = BerTlvParser.getTotalLengthBytesCount(dataBuff,
                (short) (cDataBuffOffset + 2 + msg7CByteCnt));
        short msg1EncLength = BerTlvParser.getDataLength(dataBuff,
                (short) (cDataBuffOffset + 2 + msg7CByteCnt));

        // first: get shared secret (copy in to mInData)
        short ShSSize = mCrypto.generateSecretEC_SVDP_DHC(mContext.mBuf, O_EPHEMERAL_PRIKEY2,
                EC_SK_KEY_LENGTH, mContext.mBuf, O_EPHEMERAL_PUBKEY1, EC_PK_KEY_LENGTH,
                mInData, (short)0);

        // second: random extraction K_dk
        // Z = shS.x
        // salt = E.Pub.1.x[7:0] ║ E.Pub.2.x[7:0]
        ShSSize /= 2;
        Util.arrayCopyNonAtomic(mContext.mBuf, (short) (O_EPHEMERAL_PUBKEY1 + 1), mInData,
                ShSSize, LOWER_HIGHER_BYTE_SIZE);

        Util.arrayCopyNonAtomic(mContext.mBuf, (short) (O_EPHEMERAL_PUBKEY2 + 1), mInData,
                (short) (ShSSize + LOWER_HIGHER_BYTE_SIZE), LOWER_HIGHER_BYTE_SIZE);

        // TODO: Key
        kdkLength = mCrypto.genCmacAes128(mContext.mBuf, O_KEY_PRI_ENC, EC_SK_KEY_LENGTH,
                mInData, (short) 0, (short) (ShSSize + BlOCK_16BYTES), mOutData, (short) 0);

        // third: key expansion (K_SesAuthEnc & KSCP03rootkey(delayed))
        kSesAuthEncLength = mCrypto.cmacKdfCounterModeFiRa2(mOutData, (short) 0, T_B4, T_4B,
                mOutData, kdkLength);

        // fourth: signature & certificate verification
        // decrypt Msg.1.enc (copy in to mInData), validate Cert.1 and shall then verify Sig.1
        // Msg.1.enc = ENC_CBC(KSesAuthEnc, Sig.1 ║ Cert.1 ║ Padding) with zeroed IV
        outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, mOutData, kdkLength,
                Scp3Lib.mNullBytes16, (short) 0, BlOCK_16BYTES, dataBuff,
                (short) (cDataBuffOffset + 2 + msg1EncLengthByteCnt + msg7CByteCnt),
                msg1EncLength, mInData, (short) 0);

        outLen = Crypto.unpadM2(mInData, (short) 0, outLen);
        // Now mInput has decrypted data "Sig.1 ║ Cert.1" (size = outLen) & mOutData has
        // keys till ((size = kdkLength + kSesAuthEncLength + kScp03RootLength)) 

        // Msg.1.ext= 0xE0E0 | Authentication Method | E.Pub.1 | E.Pub.2)
        short mesg1ExtLength = outLen;
        mInData[mesg1ExtLength++] = T_E0;
        mInData[mesg1ExtLength++] = T_E0;
        mInData[mesg1ExtLength++] = mContext.mBuf[O_AUTH_METHOD];
        Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY1,
                mInData, mesg1ExtLength, EC_PK_KEY_LENGTH);
        Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY2,
                mInData, (short) (mesg1ExtLength + EC_PK_KEY_LENGTH), EC_PK_KEY_LENGTH);
        mesg1ExtLength += (short) (EC_PK_KEY_LENGTH + EC_PK_KEY_LENGTH);
        mesg1ExtLength -= outLen;

        // verify certificate
        // Check first TAG '7F21'
        if (Util.getShort(mInData, (short) 64) != TAG_CERTIFICATE) // 64 is pre-calculated size
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        short dataLenByteCnt = BerTlvParser.getTotalLengthBytesCount(mInData, (short) 66);

        // verify internal of certificate (TODO: signature verification)
        if (!mCertificates.verifyCert(mInData, (short) (66 + dataLenByteCnt),
                (short) (outLen - ECD_64BYTES_SIGNATURE - 2 - dataLenByteCnt), false))
//                && !mCrypto.verifyECDSAPlainSignatureSha256(mCertificates.getPkOceEcka(), (short) 0,
//                        mCertificates.getPkOceEckaSize(), mInData,
//                        (short) 32, (short) (outLen - 32 - 64), mInData,
//                        (short) (outLen - 64), (short) 64))
        {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // TODO: key
        // Sig.1 = ECDSAsign(Priv.1, Msg.1.ext)
        if (!mCrypto.verifyECDSAPlainSignatureSha256(mContext.mBuf, O_KEY_PUB_ENC,
                EC_PK_KEY_LENGTH, mInData, outLen, mesg1ExtLength, mInData, (short) 0,
                ECD_64BYTES_SIGNATURE)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // delaying scp03rootkey calculation
        kScp03RootLength = mCrypto.cmacKdfCounterModeFiRa2(mOutData, (short) 0, T_4B, T_B4, mOutData,
                (short) (kdkLength + kSesAuthEncLength));

        // derive and store keys
        // In case of asymmetric authentication, then KSCP03rootkey computed as described
        // in 7.3.4.3.1 shall be used as root key for all keys (S-ENC, S-MAC, S-RMAC) with
        // mContext field set 32 bytes of “00”.
        short deriveKeyIndex = (short) (kdkLength + kSesAuthEncLength + kScp03RootLength);

        Util.arrayFillNonAtomic(mInData, (short) 0, (short) (BlOCK_16BYTES * 2), (byte) 0x00);

        mCommon.deriveKeys(mInData, (short) (kdkLength + kSesAuthEncLength), mInData,
                (short) (kdkLength + kSesAuthEncLength), mInData, (short) 0,
                (short) (BlOCK_16BYTES * 2), mOutData, deriveKeyIndex);

        mScp3Lib.setKeys(mOutData, deriveKeyIndex, (byte) SIGNATURE_BLOCK_SIZE);

        // generate and set UWB default key and session ID
        mCommon.generateDefaultUWBKeys(mOutData, (short) (deriveKeyIndex + SIGNATURE_BLOCK_SIZE),
                mInData, (short) 0, (short) (BlOCK_16BYTES * 2), DERIVATION_UWB_SESSION_ID, true);

        // fifth: send response
        // Table 49 – General authenticate command for asymmetric authentication (Response section)
        short msg2extIndex = 0;
        short msg2plIndex = 0;

        if (mContext.mBuf[O_AUTH_METHOD] == ASYM_MUTUAL ||
                mContext.mBuf[O_AUTH_METHOD] == ASYM_MUTUAL_SEAMLESS) {
            // Msg.2.ext = 0xE1E1 | OptsB | E.Pub.2 | E.Pub.1
            mInData[msg2extIndex++] = T_E1;
            mInData[msg2extIndex++] = T_E1;
            mInData[msg2extIndex++] = C_00;
            Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY2, mInData,
                    msg2extIndex, EC_PK_KEY_LENGTH);
            msg2extIndex += EC_PK_KEY_LENGTH;
            Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY1, mInData,
                    msg2extIndex, EC_PK_KEY_LENGTH);
            msg2extIndex += EC_PK_KEY_LENGTH;
            // mCrypto.addPaddingM2(mInData, (short) 0, msg2extIndex);
        }

        msg2plIndex = msg2extIndex;
        mInData[msg2plIndex++] = 0x00;

        if (mContext.mBuf[O_AUTH_METHOD] == ASYM_MUTUAL ||
                mContext.mBuf[O_AUTH_METHOD] == ASYM_MUTUAL_SEAMLESS) {
            // TODO: key
            // Sig.2 = ECDSAsign(Priv.2, Msg.2.ext)
            short sig2Len = mCrypto.ecdSAPlainSignatureSha256(mContext.mBuf,
                    O_EC_KEY_PRIV1, EC_SK_KEY_LENGTH, mInData,(short) 0, msg2extIndex,
                    mInData, msg2plIndex);
            msg2plIndex += sig2Len;
            msg2plIndex += ClientContext.getFiRaCert2(mInData, msg2plIndex, mFiraClientContext);
        } else {
            msg2plIndex += getADF(mInData, msg2plIndex);
        }

        msg2plIndex = (short) (Crypto.addPaddingM2(mInData, msg2extIndex,
                (short) (msg2plIndex - msg2extIndex)) + msg2extIndex);

        short msg2EncLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mOutData, kdkLength,
                Scp3Lib.mNullBytes16, (short) 0, SIGNATURE_BLOCK_SIZE, mInData, msg2extIndex,
                (short) (msg2plIndex - msg2extIndex), mInData, msg2plIndex);

        // set security level
        mCommon.setSecurityLevel(dataBuff[(short) (dataBuffOffset + ISO7816.OFFSET_P1)]);
        // set SCP status
        mContext.mBuf[O_SCP_STATUS] = SC2_GA;

        return generateMsg2(dataBuff, dataBuffOffset, dataBuffLength, mInData, msg2plIndex,
                msg2EncLen);
    }

    private short generateGA1ResponseSC1(byte[] outBuff, short outBuffOffset) {

        // Table 22 - GENERAL_AUTHENTICATE Response – Part 1
        short offset = outBuffOffset;
        {
            outBuff[offset++] = RES_7C;
            outBuff[offset++] = 0x12;
            outBuff[offset++] = T_81;
            outBuff[offset++] = 0x10; // 0x10/0x12 pre calculated value
            RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mContext.mBuf,
                    O_RANDOM_ICC, BlOCK_16BYTES);
            Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_ICC, outBuff,
                    offset, BlOCK_16BYTES);
            offset += BlOCK_16BYTES;
        }

        // Add 9000 success and return
        return (short) (Util.setShort(outBuff, offset, APDU_SUCCESS) - outBuffOffset);
    }

    private short processGA1ResponseSC1(byte[] dataBuff, short dataBuffOffset, short cDataBuffOffset,
            short cDataBuffLength, byte p2) {

        if ((cDataBuffLength > 4) && dataBuff[(short) (cDataBuffOffset + 4)] != T_83) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        if (cDataBuffLength == 4) {
            Util.setShort(mContext.mBuf, O_SC1_TAGNUMBER, p2);
        } else {
            Util.setShort(mContext.mBuf, O_SC1_TAGNUMBER,
                    dataBuff[(short) (cDataBuffOffset + 6)]);
        }

        return generateGA1ResponseSC1(dataBuff, dataBuffOffset);
    }

    private short generateGA2ResponseSC1(byte[] outBuff, short outBuffOffset, short outBuffLength,
            byte[] keyBuff, short encKeyBuffOffset, short macKeyBuffOffset) {

        // calculate "Cryptogram.ICC"
        // mInput already has "RND.IFD ║ RND.ICC ║ K.IFD ║ [Text1] ║ Padding" information at 0 offset
        // as we are not storing RND.IFD, first store/rearrange the data
        // to "RND.ICC ║ RND.IFD ║ K.ICC ║ SI ║ [Text2] ║ Padding"
        // individual size of "RND.ICC", "RND.IFD" and "K.ICC" is 16 bytes and Text2 as of now 0;
        short initialOffset = (short) (BlOCK_16BYTES * 3);
        short index = initialOffset;

        index = Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_ICC, mInData, index, BlOCK_16BYTES);
        index = Util.arrayCopyNonAtomic(mInData, (short) 0, mInData, index, BlOCK_16BYTES);

        index = RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mInData, index,
                (short) (BlOCK_16BYTES + 4));
        // NOTE:- Check text2 in future
        short outLen = Crypto.addPaddingM2(mInData, initialOffset, (short) (index - initialOffset));

        // calculate IV
        short ivLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, keyBuff,
                macKeyBuffOffset, Scp3Lib.mNullBytes16, (short) 0, BlOCK_16BYTES, mInData, initialOffset,
                BlOCK_16BYTES, mOutData, (short) 0);

        short eICCLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, keyBuff,
                encKeyBuffOffset, mOutData, (short) 0, ivLen, mInData, initialOffset,
                (short) outLen, mInData, (short) (outLen + initialOffset));

        short mICCLen = mCrypto.genCmacAes128(keyBuff, macKeyBuffOffset, SIGNATURE_BLOCK_SIZE,
                mInData, (short) (outLen + initialOffset), eICCLen, mInData,
                (short) (outLen + eICCLen + initialOffset));

        // Table 25 – GENERAL_AUTHENTICATE Response – Part 2
        short offset = outBuffOffset;
        {
            mBerTlvBuilder.startCOTag(offset);
            {
                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength, RES_82, mInData,
                        (short) (outLen + initialOffset), (short) (eICCLen + mICCLen));
            }
            offset = mBerTlvBuilder.endCOTag(outBuff, offset, RES_7C);
        }

        // before returning extract session and UWB session keys
        Util.arrayCopyNonAtomic(mInData, (short) (SIGNATURE_BLOCK_SIZE * 2), mInData,
                (short) (initialOffset + SIGNATURE_BLOCK_SIZE), SIGNATURE_BLOCK_SIZE);
        // now 64 - 96 contains "K.IFD ║ K.ICC"

        Util.arrayFillNonAtomic(mInData, (short) (initialOffset + (SIGNATURE_BLOCK_SIZE * 3)),
                (short) 15, (byte) 0x00); // // 15 is pre- calculated value
        mInData[(short) (initialOffset + (SIGNATURE_BLOCK_SIZE * 3) + 14)] = (byte) 0x80;

        // now 96 - 110 contains "0x000000000000000000000000000080"
        mCommon.setScpAndUWBsessionKey(mInData, (short) (initialOffset + (SIGNATURE_BLOCK_SIZE * 3)),
                mInData, (short) (initialOffset + SIGNATURE_BLOCK_SIZE),
                (short) (SIGNATURE_BLOCK_SIZE * 2), keyBuff, encKeyBuffOffset, macKeyBuffOffset,
                mOutData, (short) 0);

        // Add 9000 success and return
        return (short) (Util.setShort(outBuff, offset, APDU_SUCCESS) - outBuffOffset);
    }

    private short processGA2ResponseSC1(byte[] dataBuff, short dataBuffOffset, short cDataBuffOffset,
            short dataBuffLength, short sc1TagNumber, short msg7CByteCnt) {

        // {0x7C ║ L ║ {0x82 ║ Lc ║ Cryptogram.IFD}}
        // Cryptogram.IFD = E.IFD ║ M.IFD
        // E.IFD = ENC_CBC(KENC, RND.IFD ║ RND.ICC ║ K.IFD ║ [Text1] ║ Padding)
        // M.IFD = CMAC(KMAC, E.IFD)
        short cryptoIFDLen = BerTlvParser.getDataLength(dataBuff,
                (short) (cDataBuffOffset + 2 + msg7CByteCnt));
        short cryptoIFDbyteCnt = BerTlvParser.getTotalLengthBytesCount(dataBuff,
                (short) (cDataBuffOffset + 2 + msg7CByteCnt));

        // Note: The Secure Messaging Authentication Key consists of KENC (used for encryption) and
        // KMAC(used for authentication)
        short adfLen = mFiraClientContext.getKeySet(sc1TagNumber, mInData, IN_DATA_KEYSET_OFFSET);
        short encKeyOffset = ClientContext.getKeyOffet(SC1_KEYSET, ENC_KEYTYPE, mInData,
                IN_DATA_KEYSET_OFFSET, adfLen);
        short macKeyOffset = ClientContext.getKeyOffet(SC1_KEYSET, MAC_KEYTYPE, mInData,
                IN_DATA_KEYSET_OFFSET, adfLen);

        if (!mCrypto.verifyCmacAes128(mInData, encKeyOffset, SIGNATURE_BLOCK_SIZE,
                dataBuff, (short) (cDataBuffOffset + 2 + msg7CByteCnt + cryptoIFDbyteCnt),
                (short) (cryptoIFDLen - SIGNATURE_BLOCK_SIZE), dataBuff,
                (short) (cDataBuffOffset + 2 + msg7CByteCnt + cryptoIFDbyteCnt + cryptoIFDLen
                        - SIGNATURE_BLOCK_SIZE), SIGNATURE_BLOCK_SIZE)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // IV calculation
        short outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mInData, macKeyOffset,
                Scp3Lib.mNullBytes16, (short) 0, BlOCK_16BYTES, mContext.mBuf,
                O_RANDOM_ICC, BlOCK_16BYTES, mOutData, (short) 0);

        outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, mInData, macKeyOffset,
                mOutData, (short) 0, outLen, dataBuff,
                (short) (cDataBuffOffset + 2 + msg7CByteCnt + cryptoIFDbyteCnt),
                (short) (cryptoIFDLen - SIGNATURE_BLOCK_SIZE), mInData, (short) 0);

        outLen = Crypto.unpadM2(mInData, (short) 0, outLen);

        if (0 != Util.arrayCompare(mInData, SIGNATURE_BLOCK_SIZE, mContext.mBuf,
                O_RANDOM_ICC, BlOCK_16BYTES)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // NOTE:- Check text2 in future

        return generateGA2ResponseSC1(dataBuff, dataBuffOffset, dataBuffLength, mInData,
                encKeyOffset, macKeyOffset);
    }

    private short processSymmetricSC1Authentication(byte[] dataBuff, short dataBuffOffset,
            short dataBuffLength, short cDataOffset, short msg7CByteCnt) {
        byte p2 = dataBuff[(short) (dataBuffOffset + ISO7816.OFFSET_P2)];
        // Realign the offset and dataBufferLength to command data
        short cDataBuffOffset = (short) (dataBuffOffset + cDataOffset);
        short cDataBuffLength = (short) (dataBuffLength - cDataOffset);
        short sc1TagNumber = Util.getShort(mContext.mBuf, O_SC1_TAGNUMBER);

        // GA 1
        if (dataBuff[(short) (cDataBuffOffset + 2)] == T_81) {
            // set SCP status
            mContext.mBuf[O_SCP_STATUS] = SC1_GA1;
            return processGA1ResponseSC1(dataBuff, dataBuffOffset, cDataBuffOffset,
                    cDataBuffLength, p2);
        }

        // else it is GA2
        // set SCP status
        mContext.mBuf[O_SCP_STATUS] = SC1_GA2;
        return processGA2ResponseSC1(dataBuff, dataBuffOffset, cDataBuffOffset, dataBuffLength,
                sc1TagNumber, msg7CByteCnt);
    }

    private short processGA1ResponseSC2(byte[] dataBuff, short cDataBuffOffset, byte p1) {
        // Table 40- GENERAL_AUTHENTICATE – Part 1 response for symmetric authentication
        short responseLength = cDataBuffOffset;

        // ISO7816-4 header
        dataBuff[responseLength++] = T_7C;
        dataBuff[responseLength++] = T_2F;
        dataBuff[responseLength++] = T_82;
        dataBuff[responseLength++] = T_2D;

        // purpose of key Diversification data
        // https://stackoverflow.com/questions/21982556/secure-com-scp02-session-what-is-the-role-of-key-diversification-data-return
        // Key diversification data
        //  // 10 pre-calculated size
        Util.arrayFillNonAtomic(dataBuff, responseLength, (short) 10, (byte) 0x00);
        responseLength += 10;

        // Key information (for scp "i" Table 5-1: Values of Parameter “i”)
        dataBuff[responseLength++] = p1;
        dataBuff[responseLength++] = 0x03;
        dataBuff[responseLength++] = 0x70; // "i'

        // challenge 2
        Util.arrayCopyNonAtomic(mInData, BlOCK_16BYTES, dataBuff, responseLength, BlOCK_16BYTES);
        responseLength += BlOCK_16BYTES;

        // cryptogram (use S-ENC key)
        if (mScp3Lib.scp03KDF(mOutData, (short) 0, mInData, (short) 0,
                (short) (BlOCK_16BYTES * 2), CONST_CRYPTOGRAM, false, mOutData,
                (short) (BlOCK_16BYTES * 3)) != SIGNATURE_BLOCK_SIZE) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        Util.arrayCopyNonAtomic(mOutData, (short) (SIGNATURE_BLOCK_SIZE * 3), dataBuff,
                responseLength, SIGNATURE_BLOCK_SIZE);

        responseLength += SIGNATURE_BLOCK_SIZE;

        Util.arrayCopyNonAtomic(mOutData, (short) (SIGNATURE_BLOCK_SIZE * 3), mContext.mBuf,
                O_CRYPTOGRAM2, SIGNATURE_BLOCK_SIZE);

        // Add 9000 success and return
        return (short) (Util.setShort(dataBuff, responseLength, APDU_SUCCESS) - cDataBuffOffset);
    }

    private short processSymmetricSC2Authentication(byte[] dataBuff, short dataBuffOffset,
            short dataBuffLength, short cDataOffset, boolean adfPrivacy) {

        byte p1 = dataBuff[(short) (dataBuffOffset + ISO7816.OFFSET_P1)];
        byte p2 = dataBuff[(short) (dataBuffOffset + ISO7816.OFFSET_P2)];
        // Realign the offset and dataBufferLength to command data
        short cDataBuffOffset = (short) (dataBuffOffset + cDataOffset);
        short cDataBuffLength = (short) (dataBuffLength - cDataOffset);

        if (p2 == C_00) {
            if (cDataBuffLength != (short) 38) { // 38/20/10 precalculated values
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        } else if ((adfPrivacy && cDataBuffLength != (short) 38) || (!adfPrivacy &&
                cDataBuffLength != (short) 20)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if ((cDataBuffLength == (short) 38 && dataBuff[(short) (cDataBuffOffset + 20)] != T_84)
                || dataBuff[(short) (cDataBuffOffset + 3)] != (byte) 0x10) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        //  GA 1
        if (dataBuff[(short) (cDataBuffOffset + 2)] == T_81) {

            short keySetLen = mFiraClientContext.getKeySet(p1, mInData, IN_DATA_KEYSET_OFFSET);
            short macKeyOffset = ClientContext.getKeyOffet(adfPrivacy ? SC2_PRIVACY_KEYSET :
                SC2_KEYSET, MAC_KEYTYPE, mInData, IN_DATA_KEYSET_OFFSET, keySetLen);

            // if privacy is set for the ADF, verify PrivacyMAC
            if (adfPrivacy && cDataBuffLength == (short) 38 &&
                    dataBuff[(short) (cDataBuffOffset + 20)] == T_84) {
                // PrivacyMAC = CMAC(KPRIV_MAC, RandomData0 | OptsB | Device Identifier | Padding)
                Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_DATA0,
                        mInData, (short) 0, BlOCK_16BYTES);
                mInData[16] = 0x00;
                Util.arrayCopyNonAtomic(mContext.mBuf, O_DEVICE_IDENTIFIER, mInData,
                        (short) (BlOCK_16BYTES + 1), DEVICE_IDENTIFIER_SIZE);

                short inDataLength = Crypto.addPaddingM2(mInData, (short) 0,
                        (short) (DEVICE_IDENTIFIER_SIZE + BlOCK_16BYTES + 1));
                mCrypto.genCmacAes128(mInData, macKeyOffset, SIGNATURE_BLOCK_SIZE, mInData,
                        (short) 0, inDataLength, mOutData, (short) 0);

                if (Util.arrayCompare(dataBuff, (short) (cDataBuffOffset + 22), mOutData,
                        (short) 0, SIGNATURE_BLOCK_SIZE) != 0x00) {
                    // table 40:  If the check fails, a “File or application not found“ error
                    // shall be returned.
                    ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                }
            }

            // on receipt of this challenge, generates its own challenge (again random data
            // unique to this Secure Channel Session), then, using both challenges, and its
            // internal static keys, creates new secret Secure Messaging session keys1 and
            // generates a first cryptographic value ([FiRa Device 2] cryptogram)
            // using one of its newly created Secure Messaging session keys).

            // mContext (challenge1 + challenge2)
            Util.arrayCopyNonAtomic(dataBuff, (short) (cDataBuffOffset + 4), mInData, (short) 0,
                    BlOCK_16BYTES);
            RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mInData, BlOCK_16BYTES,
                    BlOCK_16BYTES);

            // derive keys
            keySetLen = mFiraClientContext.getKeySet(p1, mInData, IN_DATA_KEYSET_OFFSET);
            macKeyOffset = ClientContext.getKeyOffet(SC2_KEYSET, MAC_KEYTYPE, mInData,
            IN_DATA_KEYSET_OFFSET, keySetLen);
            short encKeyOffset = ClientContext.getKeyOffet(SC2_KEYSET, ENC_KEYTYPE,
                    mInData, IN_DATA_KEYSET_OFFSET, keySetLen);
            // In case of symmetric authentication, Key-MAC shall be used as root key for
            // S-MAC, S-RMAC, and KeyENC shall be used as root key for S-ENC.
            mCommon.deriveKeys(mInData, encKeyOffset, mInData, macKeyOffset,
                    mInData, (short) 0, (short) (BlOCK_16BYTES * 2), mOutData, (short) 0);

            mScp3Lib.setKeys(mOutData, (short) 0, (byte) SIGNATURE_BLOCK_SIZE);

            // generate and set UWB default key and session ID
            mCommon.generateDefaultUWBKeys(mOutData, SIGNATURE_BLOCK_SIZE, mInData, (short) 0,
            (short) (BlOCK_16BYTES * 2), DERIVATION_UWB_SESSION_ID, true);

            // set SCP status
            mContext.mBuf[O_SCP_STATUS] = SC2_GA1;
            return processGA1ResponseSC2(dataBuff, dataBuffOffset, p1);
        }

        // (else) 0x82, GA 2
        // verify cryptogram1
        if (Util.arrayCompare(dataBuff, (short) (cDataBuffOffset + 4), mContext.mBuf,
                O_CRYPTOGRAM2, BlOCK_16BYTES) != 0) {
            // 0x6300 Authentication of host cryptogram failed
            ISOException.throwIt((short) 0x6300);
        }

        // verify mac
        // first take backup of
        Util.arrayCopyNonAtomic(dataBuff, (short) (dataBuffOffset + dataBuffLength - BlOCK_16BYTES),
        mOutData, (short) 0, BlOCK_16BYTES);
        short tbuffLen = Crypto.addPaddingM2(dataBuff, dataBuffOffset,
                (short) (dataBuffLength - BlOCK_16BYTES));

        if (mScp3Lib.genCmac(dataBuff, dataBuffOffset, tbuffLen, mOutData,
                SIGNATURE_BLOCK_SIZE) != SIGNATURE_BLOCK_SIZE ||
                (Util.arrayCompare(mOutData, (short) 0, mOutData, SIGNATURE_BLOCK_SIZE,
                        SIGNATURE_BLOCK_SIZE) != 0)) {
            ISOException.throwIt((short) 0x6300);
        }

        mCommon.setSecurityLevel(p1);
        // set SCP status
        mContext.mBuf[O_SCP_STATUS] = SC2_GA2;

        // Table 44 – GENERAL_AUTHENTICATE – Part 2 response for symmetric authentication
        // No data to send
        // Add 9000 success and return
        return (short) (Util.setShort(dataBuff, dataBuffOffset, APDU_SUCCESS) - dataBuffOffset);
    }

    private boolean selectAdf(byte[] oidBuff, short oidBuffOffset, byte oidBuffLength) {
        if (mFiraClientContext.selectAdf(oidBuff, oidBuffOffset, oidBuffLength)) {
            Util.arrayCopyNonAtomic(oidBuff, oidBuffOffset,
                mContext.mBuf, O_SELECTED_OID, oidBuffLength);
            mContext.mBuf[O_SELECTED_OID_LEN] = oidBuffLength;
            return true;
        }

        return false;
    }

    private short generateSelectADFResponse(byte[] outBuff, short outBuffOffset, short outBuffLength,
            short tagOrSelKey, byte[] oid, short oidOffset, byte oidLength) {

        // Table 18 - SELECT ADF Response
        short offset = outBuffOffset;
        {
            mInData[0] = AES128_CBC;
            offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength, RES_CD, mInData,
                    (short) 0, (short) 1);

            RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mContext.mBuf,
                    O_RANDOM_IV, BlOCK_16BYTES);

            if (tagOrSelKey != 0 && oid != null) {
                // AlgorithmInfo ║ Cryptogram ║ MAC
                short index = 0;

                mInData[index++] = T_06;
                mInData[index++] = oidLength;
                Util.arrayCopyNonAtomic(oid, oidOffset, mInData, index, oidLength);
                index += oidLength;
                mInData[index++] = T_CF;
                mInData[index++] = DEVICE_IDENTIFIER_SIZE;
                Util.arrayCopyNonAtomic(mContext.mBuf, O_DEVICE_IDENTIFIER, mInData,
                        index, DEVICE_IDENTIFIER_SIZE);
                index += DEVICE_IDENTIFIER_SIZE;

                index = Crypto.addPaddingM2(mInData, (short) 0, index);

                // Privacy Selection Key consists of KPRIV_ENC (used for encryption) and
                // KPRIV_MAC(used for authentication)
                // E = ENC_CBC(KPRIV_ENC, {0x06 ║ L1 ║ OID} ║ {0xCF ║ L2 ║ Diversifier} ║ Padding)

                // First get key set & ENC value;
                short adfLen = mFiraClientContext.getKeySet(tagOrSelKey, mInData,
                        IN_DATA_KEYSET_OFFSET);
                short keyOffset = ClientContext.getKeyOffet(SC1_PRIVACY_KEYSET, ENC_KEYTYPE,
                        mInData, IN_DATA_KEYSET_OFFSET, adfLen);

                short eLength = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mInData,
                        keyOffset, Scp3Lib.mNullBytes16, (short) 0, BlOCK_16BYTES, mInData,
                        (short) 0, index, mOutData, (short) 0);

                // Cryptogram = {0x85 ║ L ║ (RandomData1 ║ RND.IV ║ E)}
                Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_DATA1, mInData,
                        (short) 0, BlOCK_16BYTES);
                Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_IV, mInData,
                        BlOCK_16BYTES, BlOCK_16BYTES);
                Util.arrayCopyNonAtomic(mOutData, (short) 0, mInData, (short) (BlOCK_16BYTES * 2),
                        eLength);
 
                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength, T_85, mInData,
                        (short) 0, (short) ((BlOCK_16BYTES * 2) + eLength));

                // MAC = {0x8E ║ 0x10 ║ CMAC(KPRIV_MAC, AlgorithmInfo ║ Cryptogram)}
                index = (short) (32 + eLength); // 32 pre- calculated value
                short eLengthEnd = index;

                mInData[index++] = T_CD;
                mInData[index++] = (byte) 0x01;
                mInData[index++] = AES128_CBC;
                index += BerTlvBuilder.fillLength(mInData, eLengthEnd, index);
                Util.arrayCopyNonAtomic(mInData, (short) 0, mInData, index, eLengthEnd);
                index += eLengthEnd;

                // get Mac key
                keyOffset = ClientContext.getKeyOffet(SC1_PRIVACY_KEYSET, MAC_KEYTYPE, mInData,
                        IN_DATA_KEYSET_OFFSET, adfLen);
                short macLength = mCrypto.genCmacAes128(mInData, keyOffset , SIGNATURE_BLOCK_SIZE,
                        mInData, eLengthEnd, (short) (index - eLengthEnd), mOutData, eLength);

                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength, T_8E, mOutData,
                        eLength, macLength);
            } else {
                // AlgorithmInfo ║ {0x06 ║ Lo ║ OID} ║ {0xCF ║ Ld ║ Diversifier} ║ {0x85 ║ Lr ║
                // RandomData2}

                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength, T_06, oid,
                        (short) oidOffset, (short) oidLength);
                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength, T_CF, mContext.mBuf,
                        O_DEVICE_IDENTIFIER, DEVICE_IDENTIFIER_SIZE);
                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength, T_85, mContext.mBuf,
                        O_RANDOM_DATA1, BlOCK_16BYTES);
            }
            // Add 9000 success
            offset = Util.setShort(outBuff, offset, APDU_SUCCESS);
        }
        return (short) (offset - outBuffOffset);
    }

    private short parseSelectAdfSC1(byte[] dataBuff, short dataOffset, short dataLength,
            short cDataOffset) {

        byte p1 = dataBuff[(short) (dataOffset + ISO7816.OFFSET_P1)];
        byte p2 = dataBuff[(short) (dataOffset + ISO7816.OFFSET_P2)];
        short cDataBuffOffset = (short) (dataOffset + cDataOffset);
        short cDataBuffLength = (short) (dataLength - cDataOffset);

        if (p1 != C_04) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // OID search
        short index = cDataBuffOffset;
        boolean oidMatch = false;

        while (index < cDataBuffLength) {

            if (dataBuff[index] != T_06) {
                break;
            }

            // L may have a value of up to 30. (1 byte)
            if (selectAdf(dataBuff, (short) (index + 2), dataBuff[(short) (index + 1)])) {
                oidMatch = true;
                break;
            }

            index += (2 + dataBuff[(short) (index + 1)]);
        }

        // (Table:37 CSML_r159)
        // Table 64 - ADF Extended Options
        short tagOrSelKey = p2;
        short end = (short)(index + cDataBuffLength);

        while (index < end) {

            if (dataBuff[index] == T_83) {
                // TagNumber is the tag number of a Privacy Selection Key
                tagOrSelKey = dataBuff[(short) (index + 2)];
            } else if (dataBuff[index] == T_85) {
                Util.arrayCopyNonAtomic(dataBuff, (short) (index + 2), mContext.mBuf,
                        O_RANDOM_DATA1, BlOCK_16BYTES);
            } else if (dataBuff[index] != T_06) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            index += (2 + dataBuff[(short) (index + 1)]);
        }

        // set SCP status
        mContext.mBuf[O_SCP_STATUS] = SC1_SELECT_ADF;
        return (short) (generateSelectADFResponse(dataBuff, dataOffset, cDataBuffLength,
                tagOrSelKey, oidMatch ? mContext.mBuf : null, O_SELECTED_OID,
                mContext.mBuf[O_SELECTED_OID_LEN]));
    }

    private short generateFCIdeviceIdentity(byte[] outBuff, short outBuffOffset,
            short outBuffLength) {

        short offset = outBuffOffset;
        {
            //mBerTlvBuilder.reset();
            mBerTlvBuilder.startCOTag(offset);
            {
                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength,
                                               FCI_84, mContext.mBuf, O_SELECTED_OID,
                                               (short) mContext.mBuf[O_SELECTED_OID_LEN]);

                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength,
                                               FCI_86, mContext.mBuf, O_DEVICE_IDENTIFIER,
                                               (short) DEVICE_IDENTIFIER_SIZE);
            }
            offset = mBerTlvBuilder.endCOTag(outBuff, offset, FCI_6F);
        }

        // Add 9000 success and return
        return (short) (Util.setShort(outBuff, offset, APDU_SUCCESS) - outBuffOffset);
    }

    private short generateFCIephemeralKey(byte[] outBuff, short outBuffOffset, short outBuffLength,
            boolean dummyKey) {

        short pubKeyLen = 0;
        short offset = outBuffOffset;
        {
            //mBerTlvBuilder.reset();
            mBerTlvBuilder.startCOTag(offset);
            {
                pubKeyLen = ((ECPublicKey) mEcKeyPair.getPublic()).getW(mOutData, (short) 0);
                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength,
                                               FCI_81, mOutData, (short) 0,
                                               pubKeyLen);
                if (!dummyKey) {
                    Util.arrayCopyNonAtomic(mOutData, (short) 0, mContext.mBuf,
                            O_EPHEMERAL_PUBKEY2, pubKeyLen);
                    ((ECPrivateKey) mEcKeyPair.getPrivate()).getS(mContext.mBuf,
                            O_EPHEMERAL_PRIKEY2);
                }
            }
            offset = mBerTlvBuilder.endCOTag(outBuff, offset, FCI_6F);
        }

        // Add 9000 success and return
        return (short) (Util.setShort(outBuff, offset, APDU_SUCCESS) - outBuffOffset);
    }

    // output is stored at 'mOutData' with length 16
    private void generateCryptogram(byte[] keyBuff, short encKeyBuffOffset) {

        short inDataLength = 0;

        // ENC_CBC
        mInData[inDataLength++] = 0x00;
        mInData[inDataLength++] = mContext.mBuf[O_SELECTION_INDEX];
        Util.arrayCopyNonAtomic(mContext.mBuf, O_DEVICE_IDENTIFIER, mInData, (short) 2,
                                (short) DEVICE_IDENTIFIER_SIZE);
        inDataLength += DEVICE_IDENTIFIER_SIZE;
        inDataLength = Crypto.addPaddingM2(mInData, (short) 0, inDataLength);

        // store 16 byte random data0 in 'mOutData' at '0' & copy the same to 'mRandomData0'
        RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mOutData, (short) 0, BlOCK_16BYTES);
        Util.arrayCopyNonAtomic(mOutData, (short) 0, mContext.mBuf, O_RANDOM_DATA0,
                BlOCK_16BYTES);

        // store 16 byte Cryptogram in 'mOutData' at '16'
        if (mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, keyBuff, encKeyBuffOffset,
                mContext.mBuf, O_RANDOM_DATA0, BlOCK_16BYTES, mInData, (short) 0,
                inDataLength, mOutData, SIGNATURE_BLOCK_SIZE) != SIGNATURE_BLOCK_SIZE) {
            // crypto error
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    private short generateCryptogramDO(byte[] outBuff, short outBuffOffset, short outBuffLength,
            boolean randomCrypto, byte[] keyBuff, short encKeyBuffOffset) {

        short offset = outBuffOffset;
        {
            // mBerTlvBuilder.reset();
            mBerTlvBuilder.startCOTag(offset);
            {
                if (!randomCrypto) {
                    generateCryptogram(keyBuff, encKeyBuffOffset);
                } else {
                    // store 32 byte random data1 in 'mOutData' at '0'
                    RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mOutData, (short) 0,
                            (short) (BlOCK_16BYTES * 2));
                }

                offset = BerTlvBuilder.addTlv(outBuff, offset, outBuffLength,
                        FCI_85, mOutData, (short) 0, (short) (short) (BlOCK_16BYTES * 2));
            }
            offset = mBerTlvBuilder.endCOTag(outBuff, offset, FCI_6F);
        }

        // Add 9000 success and return
        return (short) (Util.setShort(outBuff, offset, APDU_SUCCESS) - outBuffOffset);
    }

    private short responseSelectADFSC2(byte[] dataBuff, short cDataBuffOffset,
            short cDataBuffLength, byte p1, byte p2, boolean oidMatch) {
        // (Table:37 CSML_r159)
        // Table 64 - ADF Extended Options
        boolean adfPrivacy = ClientContext.getADFPrivacy(mContext.mBuf, O_SELECTED_OID,
                mContext.mBuf[O_SELECTED_OID_LEN]);

        if (p1 == C_04) {
            if (oidMatch && !adfPrivacy) {
                // send FCI
                return (short) (generateFCIdeviceIdentity(dataBuff, cDataBuffOffset,
                        cDataBuffLength) - cDataBuffOffset);
            } else if (p2 == C_00) {
                // throw FILE not found exception 
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }

            if (oidMatch && adfPrivacy) {
                // send Cryptogram
                short keySetLen = mFiraClientContext.getKeySet(p2, mInData, IN_DATA_KEYSET_OFFSET);
                short encKeyOffset = ClientContext.getKeyOffet(SC2_PRIVACY_KEYSET, ENC_KEYTYPE,
                        mInData, IN_DATA_KEYSET_OFFSET, keySetLen);
                mContext.mBuf[O_P2] = p2;
                return (short) (generateCryptogramDO(dataBuff, cDataBuffOffset, cDataBuffLength,
                        false, mInData, encKeyOffset) - cDataBuffOffset);
            }

            // send Random Cryptogram
            return (short) (generateCryptogramDO(dataBuff, cDataBuffOffset, cDataBuffLength,
                    true, null, (short) 0) - cDataBuffOffset);
        }

        // else it is an asymmetric authentication (Table:47 CSML_r159)
        mEcKeyPair.genKeyPair();
        return (short) (generateFCIephemeralKey(dataBuff, cDataBuffOffset, cDataBuffLength,
                !oidMatch) - cDataBuffOffset);
    }

    //
    // One alternative would be for a FiRa Device to select the ADF using symmetric keys first and
    // if unsuccessful try using asymmetric keys. To avoid these two successive selections, Secure
    // Channel 2 provides a seamless authentication method switch feature where an ADF selected with
    // asymmetric keys may respond using symmetric keys provided the following conditions are met:
    // • the SELECT_ADF options allow switching to symmetric authentication
    // • the configuration of the ADF allows switching to symmetric authentication
    // • FiRa Device 2 is provisioned with symmetric keys (e.g., after a successful asymmetric
    // authentication, a FiRa Device 1 has updated the ADF of FiRa Device 2 with symmetric keys at
    // a previous point in time).
    private short parseSelectAdfSC2(byte[] dataBuff, short dataOffset, short dataLength,
            short cDataOffset) {

        byte p1 = dataBuff[(short) (dataOffset + ISO7816.OFFSET_P1)];
        byte p2 = dataBuff[(short) (dataOffset + ISO7816.OFFSET_P2)];
        short cDataBuffOffset = (short) (dataOffset + cDataOffset);
        short cDataBuffLength = (short) (dataLength - cDataOffset);
        byte authMethod = dataBuff[(short) (cDataBuffOffset + 2)];

        switch (authMethod) {
            case SYM:
            case ASYM_UNILATERAL:
            case ASYM_UNILATERAL_SEAMLESS:
            case ASYM_MUTUAL:
            case ASYM_MUTUAL_SEAMLESS:
                mContext.mBuf[O_AUTH_METHOD] = authMethod;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // OID search
        short index = 0;
        short rDataLength = 0;
        boolean oidMatch = false;
        mContext.mBuf[O_SELECTION_INDEX] = 0;

        if (p1 == C_04) {
            // symmetric authentication
            index = (short) (3 + cDataBuffOffset);
            rDataLength = (short) (index + cDataBuffLength - 3);

        } else if (p1 == C_00) {
            // TODO: Check whether Authentication method is supported by Application

            // Asymmetric authentication
            if (dataBuff[(short) (cDataBuffOffset + 3)] != T_81) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // copy ephemeral key FiRa 1
            Util.arrayCopyNonAtomic(dataBuff, (short) (cDataBuffOffset + 5),
                    mContext.mBuf, O_EPHEMERAL_PUBKEY1, EC_PK_KEY_LENGTH);

            index = (short) (5 + EC_PK_KEY_LENGTH + cDataBuffOffset);
            rDataLength = (short) (index + cDataBuffLength - (5 + EC_PK_KEY_LENGTH));

        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        while (index < rDataLength) {

            if (dataBuff[index] != T_06) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // L may have a value of up to 30. (1 byte)
            if (selectAdf(dataBuff, index, dataBuff[(short) (index + 2)])) {
                oidMatch = true;
                break;
            }

            index += (2 + dataBuff[(short) (index + 1)]);
            mContext.mBuf[O_SELECTION_INDEX]++;
        }

        // set SCP status
        mContext.mBuf[O_SCP_STATUS] = authMethod == SYM ? SC2_SELECT_ADF_SYS : SC2_SELECT_ADF_ASYS;

        return responseSelectADFSC2(dataBuff, dataOffset, cDataBuffLength, p1, p2, oidMatch);
    }

    // Public functions
    public short parseSelectAdf(byte[] dataBuff, short dataOffset, short dataLength,
            short cDataOffset) {

        short cDataBuffOffset = (short) (dataOffset + cDataOffset);

        if (dataBuff[cDataBuffOffset] == T_06) {
            // Table:17 (CSML_r159)
            return parseSelectAdfSC1(dataBuff, dataOffset, dataLength, cDataOffset);
        } else if (dataBuff[cDataBuffOffset] == T_80 && dataBuff[(short) (cDataBuffOffset + 1)]
                == 0x01) {
            // check OptsA (Table:35/46 CSML_r159)
            return parseSelectAdfSC2(dataBuff, dataOffset, dataLength, cDataOffset);
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return 0;
    }

    public short processGeneralAuthentication(byte[] dataBuff, short dataBuffOffset,
            short dataBuffLength, short cDataOffset) {

        boolean adfPrivacy = ClientContext.getADFPrivacy(mContext.mBuf, O_SELECTED_OID,
                mContext.mBuf[O_SELECTED_OID_LEN]);
        short cDataBuffOffset = (short) (dataBuffOffset + cDataOffset);

        if (dataBuff[cDataBuffOffset] != T_7C)
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        short msg7CByteCnt = BerTlvParser.getTotalLengthBytesCount(dataBuff,
                (short) (cDataBuffOffset + 1));
        short offsetMsg7cData = (short) (cDataBuffOffset + msg7CByteCnt + 1);

        if ((dataBuff[offsetMsg7cData] == T_81 && dataBuff[(short) (offsetMsg7cData + 1)] == C_00)
                || (dataBuff[offsetMsg7cData] == T_82 && dataBuff[ISO7816.OFFSET_P1]
                        == (byte) 0x00)) {
            return processSymmetricSC1Authentication(dataBuff, dataBuffOffset, dataBuffLength,
                    cDataOffset, msg7CByteCnt);
        } else if((dataBuff[offsetMsg7cData] == T_81 || dataBuff[offsetMsg7cData] == T_82)) {
            return processSymmetricSC2Authentication(dataBuff, dataBuffOffset, dataBuffLength,
                    cDataOffset, adfPrivacy);
        } else if (dataBuff[offsetMsg7cData] == T_86) {
            return processAsymmetricSC2Authentication(dataBuff, dataBuffOffset, dataBuffLength,
                    cDataOffset, msg7CByteCnt);
        }

        return 0;
    }

}
