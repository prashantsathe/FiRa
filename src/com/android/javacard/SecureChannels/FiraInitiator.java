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
import static com.android.javacard.SecureChannels.FiraContext.*;

import com.android.javacard.ber.BerTlvBuilder;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class FiraInitiator {

    private FiraContext mContext;
    private FiraClientContext mFiraClientContext;
    private Crypto mCrypto;
    private KeyPair mEcKeyPair;
    private Scp3Lib mScp3Lib;
    private FiraCommon mCommon;

    private byte[] mInData;
    private byte[] mOutData;

    public FiraInitiator(FiraContext context, FiraClientContext firaClientContext, Crypto crypto,
            KeyPair ecKeyPair, Scp3Lib scp3Lib, FiraCommon common, byte[] inData, byte[] outData) {
        mContext = context;
        mFiraClientContext = firaClientContext;
        mCrypto = crypto;
        mEcKeyPair = ecKeyPair;
        mScp3Lib = scp3Lib;
        mCommon = common;
        mInData = inData;
        mOutData = outData;
    }

    private short getGA1CmdSC1(byte[] buffer, short bufferOffset, short secureMsgAuthKey) {

        short index = bufferOffset;
        boolean tagNumberPresent = secureMsgAuthKey == 0 ? false : (secureMsgAuthKey > 31 ?
                true : false);

        // CLA/INS/P1P2
        buffer[index++] = C_00; // (or 0x0C when used during an ongoing Secure Messaging session)
        buffer[index++] = INS_GA1_GA2;
        buffer[index++] = C_00;
        mContext.mBuf[O_P2] = buffer[index++] = tagNumberPresent ? C_00 :
            (byte) secureMsgAuthKey;

        // The extended length APDU fields shall be supported.
        buffer[index++] = C_00;
        buffer[index++] = C_00;
        buffer[index++] = (byte) 7;

        // {0x7C ║ L ║ ({0x81 ║ 0x00} ║ [0x83 ║ Lt ║ TagNumber])}
        buffer[index++] = T_7C;
        buffer[index++] = (byte) (tagNumberPresent ? 0x05 : 0x02); // 0x05/02 predefined values
        buffer[index++] = T_81;
        buffer[index++] = C_00;

        if (tagNumberPresent) {
            buffer[index++] = T_83;
            buffer[index++] = 0x01;
            buffer[index++] = (byte) secureMsgAuthKey;
            Util.setShort(mContext.mBuf, O_SC1_TAGNUMBER, secureMsgAuthKey);
        } else {
            Util.setShort(mContext.mBuf, O_SC1_TAGNUMBER, (short) 0);
        }

        return (short) (index - bufferOffset);
    }

    private short getGA2CmdSC1(byte[] buffer, short bufferOffset) {

        short index = bufferOffset;
        short cryptoIFDLen = 0;
        short sc1TagNumber = Util.getShort(mContext.mBuf, O_SC1_TAGNUMBER);

        // CLA/INS/P1P2
        buffer[index++] = C_00;
        buffer[index++] = INS_GA1_GA2;
        buffer[index++] = C_00;
        buffer[index++] = mContext.mBuf[O_P2];

        // {0x7C ║ L ║ {0x82 ║ Lc ║ Cryptogram.IFD}}
        // Cryptogram.IFD = E.IFD ║ M.IFD
        // E.IFD = ENC_CBC(KENC, RND.IFD ║ RND.ICC ║ K.IFD ║ [Text1] ║ Padding)
        // M.IFD = CMAC(KMAC, E.IFD)

        // IV calculation
        short keySetLen = mFiraClientContext.getKeySet(mContext.mBuf[O_P2] == 0 ?
                sc1TagNumber : mContext.mBuf[O_P2], mInData, IN_DATA_KEYSET_OFFSET);
        short macKeyOffset = ClientContext.getKeyOffet(SC1_KEYSET, MAC_KEYTYPE,
                mInData, IN_DATA_KEYSET_OFFSET, keySetLen);
        short encKeyOffset = ClientContext.getKeyOffet(SC1_KEYSET, ENC_KEYTYPE,
                mInData, IN_DATA_KEYSET_OFFSET, keySetLen);

        short outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mInData, macKeyOffset,
                Scp3Lib.mNullBytes16, (short) 0, SIGNATURE_BLOCK_SIZE, mContext.mBuf,
                O_RANDOM_ICC, SIGNATURE_BLOCK_SIZE, mOutData, (short) 0);

        RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mContext.mBuf,
                O_RANDOM_IFD, BlOCK_16BYTES);
        RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mContext.mBuf,
                O_KIFD, BlOCK_16BYTES);
        Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_IFD, mInData, (short) 0, BlOCK_16BYTES);
        Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_ICC, mInData, BlOCK_16BYTES, BlOCK_16BYTES);
        Util.arrayCopyNonAtomic(mContext.mBuf, O_KIFD, mInData, (short) (BlOCK_16BYTES * 2),
                BlOCK_16BYTES);

        // NOTE:- Check text2 in future
        short inLen = Crypto.addPaddingM2(mInData, (short) 0, (short) (BlOCK_16BYTES * 3));

        // E.IFD
        short eIFDLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mInData, encKeyOffset,
                mOutData, (short) 0, outLen, mInData, (short) 0, inLen, mInData, inLen);

        // M.IFD
        short mIFDLen = mCrypto.genCmacAes128(mInData, macKeyOffset, SIGNATURE_BLOCK_SIZE, mInData,
                inLen, eIFDLen, mInData, (short) (inLen + eIFDLen));

        cryptoIFDLen = (short) (eIFDLen + mIFDLen);

        // The extended length APDU fields shall be supported.
        buffer[index++] = C_00;
        // save length offset to store length value later time
        short lenOffset = index;
        index += 2;

        buffer[index++] = T_7C;
        index += BerTlvBuilder.fillLength(buffer,
                (short) (cryptoIFDLen + 1 + (cryptoIFDLen < 0x80 ? 1 :
                    (cryptoIFDLen < 0x100 ? 2 : 3))), index);

        buffer[index++] = T_82;
        index += BerTlvBuilder.fillLength(buffer, cryptoIFDLen, index);
        index = Util.arrayCopyNonAtomic(mInData, inLen, buffer, index, cryptoIFDLen);
        Util.setShort(buffer, lenOffset, (short) (index - (lenOffset + 2)));

        return (short)(index - bufferOffset);
    }

    private short getGA1SymmetricCmdSC2(byte[] buffer, short bufferOffset, byte kvn,
            byte kid) {

        short index = bufferOffset;
        boolean privacy = ClientContext.getADFPrivacy(mContext.mBuf, O_SELECTED_OID,
                mContext.mBuf[O_SELECTED_OID_LEN]);

        buffer[index++] = C_00; //0x00 (or 0x0C for Secure Messaging)
        buffer[index++] = INS_GA1_GA2;
        buffer[index++] = kvn;
        buffer[index++] = kid;

        // The extended length APDU fields shall be supported.
        buffer[index++] = C_00;
        buffer[index++] = C_00;
        if (privacy) {
            buffer[index++] = 0x14; // pre-calculated values
        } else {
            buffer[index++] = 0x26;
        }

        buffer[index++] = T_7C;
        buffer[index++] = (byte) 0x12;
        buffer[index++] = T_81;
        buffer[index++] = (byte) 0x10;
        RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mContext.mBuf, O_CHALLENGE1,
                BlOCK_16BYTES);
        index = Util.arrayCopyNonAtomic(mContext.mBuf, O_CHALLENGE1, buffer, index, BlOCK_16BYTES);

        if (privacy) {
            // PrivacyMAC = CMAC(KPRIV_MAC, RandomData0 | OptsB | Device Identifier | Padding)
            Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_DATA0,
                    mInData, (short) 0, BlOCK_16BYTES);
            mInData[16] = 0x00;
            Util.arrayCopyNonAtomic(mContext.mBuf, O_DEVICE_IDENTIFIER,
                    mInData, (short) (BlOCK_16BYTES + 1), DEVICE_IDENTIFIER_SIZE);
            short length = Crypto.addPaddingM2(mInData, (short) 0,
                    (short) (DEVICE_IDENTIFIER_SIZE + BlOCK_16BYTES + 1));

            short keySetLen = mFiraClientContext.getKeySet(mContext.mBuf[O_P2],
                    mInData, IN_DATA_KEYSET_OFFSET);
            short macKeyOffset = ClientContext.getKeyOffet(SC2_PRIVACY_KEYSET, MAC_KEYTYPE,
                    mInData, IN_DATA_KEYSET_OFFSET, keySetLen);
            length = mCrypto.genCmacAes128(mInData, macKeyOffset, SIGNATURE_BLOCK_SIZE, mInData,
                    (short) 0, length, mOutData, (short) 0);

            buffer[index++] = T_84;
            buffer[index++] = (byte) 0x10;
            index = Util.arrayCopyNonAtomic(mOutData, (short) 0, buffer, index, length);
        }

        return (short) (index - bufferOffset);
    }

    private short getGA2SymmetricCmdSC2(byte[] buffer, short bufferOffset, byte securityLevel,
            byte kvn) {

        short index = bufferOffset;

        buffer[index++] = C_00;
        buffer[index++] = INS_GA1_GA2;
        buffer[index++] = securityLevel;
        buffer[index++] = C_00;

        // The extended length APDU fields shall be supported.
        buffer[index++] = C_00;
        buffer[index++] = C_00;
        buffer[index++] = 0x26; // pre-calculated value

        buffer[index++] = T_7C;
        buffer[index++] = (byte) 0x24;
        buffer[index++] = T_82;
        buffer[index++] = (byte) 0x10;

        // Cryptogram1 calculation start
        Util.arrayCopyNonAtomic(mContext.mBuf, O_CHALLENGE1,
                mInData, (short) 0, BlOCK_16BYTES);
        Util.arrayCopyNonAtomic(mContext.mBuf, O_CHALLENGE2,
                mInData, BlOCK_16BYTES, BlOCK_16BYTES);

        // In case of symmetric authentication, Key-MAC shall be used as root key
        // for S-MAC, S-RMAC, and KeyENC shall be used as root key for S-ENC.
        short keySetLen = mFiraClientContext.getKeySet(kvn, mInData, IN_DATA_KEYSET_OFFSET);
        short macKeyOffset = ClientContext.getKeyOffet(SC2_KEYSET, MAC_KEYTYPE, mInData,
                IN_DATA_KEYSET_OFFSET, keySetLen);
        short encKeyOffset = ClientContext.getKeyOffet(SC2_KEYSET, ENC_KEYTYPE, mInData,
                IN_DATA_KEYSET_OFFSET, keySetLen);

        mCommon.deriveKeys(mInData, encKeyOffset, mInData, macKeyOffset,
                mInData, (short) 0, (short) (BlOCK_16BYTES * 2), mOutData, (short) 0);

        mScp3Lib.setKeys(mOutData, (short) 0, (byte) SIGNATURE_BLOCK_SIZE);

        // generate and set UWB default key and session ID
        mCommon.generateDefaultUWBKeys(mOutData, SIGNATURE_BLOCK_SIZE, mInData, (short) 0,
                (short) (SIGNATURE_BLOCK_SIZE * 2), DERIVATION_UWB_SESSION_ID, true);

        short len = mScp3Lib.scp03KDF(mOutData, (short) 0, mInData, (short) 0,
                (short) (SIGNATURE_BLOCK_SIZE * 2), CONST_CRYPTOGRAM, false, mOutData,
                (short) (SIGNATURE_BLOCK_SIZE * 3));
        // Cryptogram1 calculation end

        index = Util.arrayCopyNonAtomic(mOutData, (short) (SIGNATURE_BLOCK_SIZE * 3), buffer,
                index, len);
        buffer[index++] = T_84;
        buffer[index++] = (byte) 0x10;

        // MAC1 calculation start
        short dataLen = Crypto.addPaddingM2(buffer, bufferOffset, index);

        dataLen = mScp3Lib.genCmac(buffer, bufferOffset, dataLen, mOutData, (short) 0);
        // MAC1 calculation end
        index = Util.arrayCopyNonAtomic(mOutData, (short) 0, buffer, index, dataLen);

        mCommon.setSecurityLevel(securityLevel);
        return (short) (index - bufferOffset);
    }

    private short getGAAsymmetricCmdSC2(byte[] buffer, short bufferOffset, byte securityLevel,
            byte kvn) {

        short index = bufferOffset;

        buffer[index++] = C_00;
        buffer[index++] = INS_GA1_GA2;
        buffer[index++] = securityLevel;
        buffer[index++] = C_00;

        // calculate Msg.1.enc
        // first: get shared secret (copy in to mInData)
        short ShSSize = mCrypto.generateSecretEC_SVDP_DHC(mContext.mBuf, O_EPHEMERAL_PRIKEY1,
                EC_SK_KEY_LENGTH, mContext.mBuf, O_EPHEMERAL_PUBKEY2, EC_PK_KEY_LENGTH,
                mInData, (short) 0);

        // second: random extraction K_dk
        // Z = shS.x
        // salt = E.Pub.1.x[7:0] ║ E.Pub.2.x[7:0]
        ShSSize /= 2;
        Util.arrayCopyNonAtomic(mContext.mBuf, (short) (O_EPHEMERAL_PUBKEY1 + 1), mInData,
                ShSSize, LOWER_HIGHER_BYTE_SIZE);

        Util.arrayCopyNonAtomic(mContext.mBuf, (short) (O_EPHEMERAL_PUBKEY2 + 1), mInData,
                (short) (ShSSize + LOWER_HIGHER_BYTE_SIZE), LOWER_HIGHER_BYTE_SIZE);

        // TODO: Key
        short kdkLength = mCrypto.genCmacAes128(mContext.mBuf, O_KEY_PRI_ENC, EC_SK_KEY_LENGTH,
                mInData, (short) 0, (short) (ShSSize + BlOCK_16BYTES), mOutData, (short) 0);

        // third: key expansion (K_SesAuthEnc)
        short kSesAuthEncLength = mCrypto.cmacKdfCounterModeFiRa2(mOutData, (short) 0, T_B4,
                T_4B, mOutData, kdkLength);

        // save K_SesAuthEnc
        Util.arrayCopyNonAtomic(mOutData, kdkLength, mContext.mBuf, O_KSES_AUTHENC,
                kSesAuthEncLength);

        // Msg.1.ext= 0xE0E0 | Authentication Method | E.Pub.1 | E.Pub.2)
        short mesg1ExtLength = 0;
        mInData[mesg1ExtLength++] = T_E0;
        mInData[mesg1ExtLength++] = T_E0;
        mInData[mesg1ExtLength++] = mContext.mBuf[O_AUTH_METHOD];
        Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY1, mInData,
                mesg1ExtLength, EC_PK_KEY_LENGTH);
        Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY2, mInData,
                (short) (mesg1ExtLength + EC_PK_KEY_LENGTH), EC_PK_KEY_LENGTH);
        mesg1ExtLength += (short) (EC_PK_KEY_LENGTH + EC_PK_KEY_LENGTH);

        // TODO: key
        // Sig.1 = ECDSAsign(Priv.1, Msg.1.ext)
        short keySetLen = mFiraClientContext.getKeySet(mContext.mBuf[O_P2],
                mInData, IN_DATA_KEYSET_OFFSET);
        // short encKeyOffset = ((AdfStore) mFiraClientContext[0]).getKeyOffet(SC2_KEYSET, PRIVATE_KEYTYPE, mInData,
        // IN_DATA_KEYSET_OFFSET, keySetLen);
        short mesgLen = mCrypto.ecdSAPlainSignatureSha256(mContext.mBuf, O_EC_KEY_PRIV1,
                EC_SK_KEY_LENGTH, mInData, (short) 0, mesg1ExtLength, mInData, mesg1ExtLength);
        mesgLen += ClientContext.getFiRaCert2(mInData, (short) (mesg1ExtLength + mesgLen),
                mFiraClientContext);
        mesgLen = Crypto.addPaddingM2(mInData, mesg1ExtLength, mesgLen);

        // mesgEncLen now contains actual Msg.1.enc length
        short mesgEncLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mOutData, kdkLength,
                Scp3Lib.mNullBytes16, (short) 0, BlOCK_16BYTES, mInData, mesg1ExtLength, mesgLen,
                mInData, (short) (mesg1ExtLength + mesgLen));

        //////////////////////////////////////////////
        // now derive keys
        // delaying scp03rootkey calculation
        short kScp03RootLength = mCrypto.cmacKdfCounterModeFiRa2(mOutData, (short) 0, T_4B, T_B4,
                mOutData, (short) (kdkLength + kSesAuthEncLength));

        // derive and store the keys
        // In case of asymmetric authentication, then KSCP03rootkey computed as
        // described in 7.3.4.3.1 shall be used as root key for all keys (S-ENC,
        // S-MAC, S-RMAC) with mContext field set 32 bytes of “00”.
        short deriveKeyIndex = (short) (kdkLength + kSesAuthEncLength + kScp03RootLength);
        short contextIndex = (short) (mesg1ExtLength + mesgLen + mesgEncLen);

        Util.arrayFillNonAtomic(mInData, (short) contextIndex, (short) (SIGNATURE_BLOCK_SIZE * 2),
                C_00);

        mCommon.deriveKeys(mOutData, (short) (kdkLength + kSesAuthEncLength), mOutData,
                (short) (kdkLength + kSesAuthEncLength), mInData, contextIndex,
                (short) (SIGNATURE_BLOCK_SIZE * 2), mOutData, deriveKeyIndex);

        mScp3Lib.setKeys(mOutData, deriveKeyIndex, (byte) BlOCK_16BYTES);

        // generate and set UWB default key and session ID
        mCommon.generateDefaultUWBKeys(mOutData, (short) (deriveKeyIndex + SIGNATURE_BLOCK_SIZE),
                mInData, (short) 0, (short) (SIGNATURE_BLOCK_SIZE * 2), DERIVATION_UWB_SESSION_ID, true);
        /////////////////////////////////////////////////////////////

        short nuBytesCntMesgEnc  = (short) ((mesgEncLen < 0x80) ? 1 : (mesgEncLen < 0x100 ? 2 : 3));
        short nuBytesCnt7C  = (short) ((short) (mesgEncLen + nuBytesCntMesgEnc + 1) < (short) 0x80 ? 1 :
            ((short) (mesgEncLen + nuBytesCntMesgEnc + 1) < (short) 0x100 ? 2 : 3));
        short lc = (short) (mesgEncLen + nuBytesCntMesgEnc + nuBytesCnt7C + 2);

        // The extended length APDU fields shall be supported.
        buffer[index++] = C_00;
        index = Util.setShort(buffer, index, lc);

        buffer[index++] = T_7C;
        index += BerTlvBuilder.fillLength(buffer, (short) (mesgEncLen + nuBytesCntMesgEnc + 1), index);

        buffer[index++] = T_86;
        index += BerTlvBuilder.fillLength(buffer, mesgEncLen, index);

        return (short) (Util.arrayCopyNonAtomic(mInData, (short) (mesg1ExtLength + mesgLen), buffer,
                index, mesgEncLen) - bufferOffset);
    }

    // Public functions
    public short getGA(byte[] buffer, short bufferOffset, short kvn, short kid, byte securityLevel) {

        if (mContext.mBuf[O_SCP_STATUS] == SC2_SELECT_ADF_ASYS) {
            mContext.mBuf[O_SCP_STATUS] = SC2_GA;
            return getGAAsymmetricCmdSC2(buffer, bufferOffset, securityLevel, (byte) kvn /*SC KVN*/);
        } else if (mContext.mBuf[O_SCP_STATUS] == SC2_SELECT_ADF_SYS) {
            mContext.mBuf[O_SCP_STATUS] = SC2_GA1;
            return getGA1SymmetricCmdSC2(buffer, bufferOffset, (byte) kvn /*SC KVN*/, (byte) kid);
        } else if (mContext.mBuf[O_SCP_STATUS] == SC1_SELECT_ADF) {
            mContext.mBuf[O_SCP_STATUS] = SC1_GA1;
            return getGA1CmdSC1(buffer, bufferOffset, kvn /*SC kvn*/);
        } else if (mContext.mBuf[O_SCP_STATUS] == SC2_GA1) {
            mContext.mBuf[O_SCP_STATUS] = SC2_GA2;
            return getGA2SymmetricCmdSC2(buffer, bufferOffset, securityLevel, (byte) kvn /*SC KVN*/);
        } else if (mContext.mBuf[O_SCP_STATUS] == SC1_GA1) {
            mContext.mBuf[O_SCP_STATUS] = SC1_GA2;
            return getGA2CmdSC1(buffer, bufferOffset);
        }

        return ERROR;
    }

    public short getSelectADFCmdSC1(byte[] buffer, short bufferOffset, byte[] oidData,
            short oidDataOffset, short oidDataLength, short privacySelKey) {

        short index = bufferOffset;
        boolean tagNumberPresent = privacySelKey == 0 ? false : (privacySelKey > 31 ? true : false);

        // CLA/INS/P1P2
        buffer[index++] = T_80;
        buffer[index++] = INS_SELECT_ADF;
        buffer[index++] = C_04;
        buffer[index++] = tagNumberPresent ? (byte) 0x00 : (byte) privacySelKey;

        // The extended length APDU fields shall be supported.
        buffer[index++] = 0x00;
        // 21 is subsequent pre-calculated length
        index = Util.setShort(buffer, index, (short) (oidDataLength + 21));

        // {T1 ║ L1 ║ OID1} [ ║ … ║ {Tn ║ Ln ║ OIDn}] ║ [‘83’ ║ Lt ║ TagNumber] ║ {‘85’ ║ Lr ║RandomData1}
        index = Util.arrayCopyNonAtomic(oidData, oidDataOffset, buffer, index, oidDataLength);

        if (tagNumberPresent) {
            buffer[index++] = T_83;
            buffer[index++] = (byte) 0x01;
            buffer[index++] = (byte) privacySelKey;
        }

        buffer[index++] = T_85;
        buffer[index++] = (byte) BlOCK_16BYTES;

        mContext.mBuf[O_SCP_STATUS] = SC1_SELECT_ADF;

        RandomData.getInstance(RandomData.ALG_FAST).nextBytes(mContext.mBuf,
                O_RANDOM_DATA1, BlOCK_16BYTES);
        return (short) (Util.arrayCopyNonAtomic(mContext.mBuf, O_RANDOM_DATA1,
                buffer, index, BlOCK_16BYTES) - bufferOffset);
    }

    public short getSelectADFCmdSC2(byte[] buffer, short bufferOffset, byte[] oidData,
            short oidDataOffset, short oidDataLength, byte keyRef, byte authMethod) {

        short index = bufferOffset;
        short dataLen = (authMethod != SYM) ? (short) (oidDataLength + 6) :
            (short) (oidDataLength + 3);

        // CLA/INS/P1P2
        buffer[index++] = T_80;
        buffer[index++] = INS_SELECT_ADF;
        buffer[index++] = (authMethod != SYM) ? C_00 : C_04;
        mContext.mBuf[O_P2] = buffer[index++] = keyRef;

        // The extended length APDU fields shall be supported.
        buffer[index++] = C_00;
        index = Util.setShort(buffer, index, dataLen);

        buffer[index++] = T_80;
        buffer[index++] = (byte) 0x01;
        buffer[index++] = authMethod;

        if (authMethod != SYM) {
            mEcKeyPair.genKeyPair();
            ((ECPublicKey) mEcKeyPair.getPublic()).getW(mContext.mBuf, O_EPHEMERAL_PUBKEY1);
            ((ECPrivateKey) mEcKeyPair.getPrivate()).getS(mContext.mBuf, O_EPHEMERAL_PRIKEY1);
            buffer[index++] = (byte) 0x81;
            buffer[index++] = EC_PK_KEY_LENGTH;
            index = Util.arrayCopyNonAtomic(mContext.mBuf, O_EPHEMERAL_PUBKEY1, buffer,
                    index, EC_PK_KEY_LENGTH);
            mContext.mBuf[O_SCP_STATUS] = SC2_SELECT_ADF_ASYS;
        } else {
            mContext.mBuf[O_SCP_STATUS] = SC2_SELECT_ADF_SYS;
        }

        mContext.mBuf[O_AUTH_METHOD] = authMethod;
        return (short) (Util.arrayCopyNonAtomic(oidData, oidDataOffset, buffer, index,
                oidDataLength) - bufferOffset);
    }
}
