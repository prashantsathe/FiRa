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

import static com.android.javacard.SecureChannels.ScpConstant.*;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class Crypto {

    private KeyPair mEcKeyPair;
    // P-256 Curve Parameters
    private static byte[] sSecp256r1_P;
    private static byte[] sSecp256r1_A;
    private static byte[] sSecp256r1_B;
    private static byte[] sSecp256r1_S;
    // Uncompressed form
    private static byte[] sSecp256r1_UCG;
    private static byte[] sSecp256r1_N;
    private static final short sSecp256r1_H = 1;

    private KeyAgreement mKeyAgreement;
    private Signature mMacSignature128;
    private Signature mSignerEcdsaPlain;
    private Cipher mAesCipher;
    private Cipher mAesCipherT;

    private byte[] mInputData;

    public Crypto() {
        mEcKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        initStatics();
        initECKey(mEcKeyPair);
        mInputData = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_RESET);
        mMacSignature128 = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        mSignerEcdsaPlain = Signature.getInstance(MessageDigest.ALG_SHA_256,
                Signature.SIG_CIPHER_ECDSA_PLAIN, Cipher.PAD_NULL, false);
        mAesCipher = (Cipher) Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        mAesCipherT = (Cipher) Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
    }

    // Only require in jcop simulator
    private static void initStatics() {
        sSecp256r1_P = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

        sSecp256r1_A = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFC };

        sSecp256r1_B = new byte[] { (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA,
                (byte) 0x3A, (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD,
                (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC, (byte) 0x65,
                (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0,
                (byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27,
                (byte) 0xD2, (byte) 0x60, (byte) 0x4B };

        sSecp256r1_S = new byte[] { (byte) 0xC4, (byte) 0x9D, (byte) 0x36, (byte) 0x08, (byte) 0x86,
                (byte) 0xE7, (byte) 0x04, (byte) 0x93, (byte) 0x6A, (byte) 0x66, (byte) 0x78,
                (byte) 0xE1, (byte) 0x13, (byte) 0x9D, (byte) 0x26, (byte) 0xB7, (byte) 0x81,
                (byte) 0x9F, (byte) 0x7E, (byte) 0x90 };

        // Uncompressed form
        sSecp256r1_UCG = new byte[] { (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1,
                (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8,
                (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40,
                (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D,
                (byte) 0xEB, (byte) 0x33, (byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39,
                (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96, (byte) 0x4F,
                (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F,
                (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C,
                (byte) 0x0F, (byte) 0x9E, (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33,
                (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE, (byte) 0xCB,
                (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51,
                (byte) 0xF5 };

        sSecp256r1_N = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xBC,
                (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E,
                (byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC,
                (byte) 0x63, (byte) 0x25, (byte) 0x51 };
    }

    public static void initECKey(KeyPair ecKeyPair) {
        ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
        ECPublicKey pubkey = (ECPublicKey) ecKeyPair.getPublic();
        pubkey.setFieldFP(sSecp256r1_P, (short) 0, (short) sSecp256r1_P.length);
        pubkey.setA(sSecp256r1_A, (short) 0, (short) sSecp256r1_A.length);
        pubkey.setB(sSecp256r1_B, (short) 0, (short) sSecp256r1_B.length);
        pubkey.setG(sSecp256r1_UCG, (short) 0, (short) sSecp256r1_UCG.length);
        pubkey.setK(sSecp256r1_H);
        pubkey.setR(sSecp256r1_N, (short) 0, (short) sSecp256r1_N.length);

        privKey.setFieldFP(sSecp256r1_P, (short) 0, (short) sSecp256r1_P.length);
        privKey.setA(sSecp256r1_A, (short) 0, (short) sSecp256r1_A.length);
        privKey.setB(sSecp256r1_B, (short) 0, (short) sSecp256r1_B.length);
        privKey.setG(sSecp256r1_UCG, (short) 0, (short) sSecp256r1_UCG.length);
        privKey.setK(sSecp256r1_H);
        privKey.setR(sSecp256r1_N, (short) 0, (short) sSecp256r1_N.length);
    }

    public boolean verifyECDSAPlainSignatureSha256(byte[] pubKey, short pubKeyOffset,
            short pubKeyLen, byte[] inputDataBuf, short inputDataStart, short inputDataLength,
            byte[] sigBuffer, short sigOffset, short sigLength) {
        ECPublicKey key = (ECPublicKey) mEcKeyPair.getPublic();
        key.setW(pubKey, pubKeyOffset, pubKeyLen);
        mSignerEcdsaPlain.init(key, Signature.MODE_VERIFY);
        return mSignerEcdsaPlain.verify(inputDataBuf, inputDataStart, inputDataLength, sigBuffer,
                sigOffset, sigLength);
    }

    public short ecdSAPlainSignatureSha256(byte[] priKey, short priKeyOffset, short priKeyLen,
            byte[] inputDataBuf, short inputDataStart, short inputDataLength, byte[] sigBuffer,
            short sigOffset) {
        ECPrivateKey key = (ECPrivateKey) mEcKeyPair.getPrivate();
        key.setS(priKey, priKeyOffset, priKeyLen);
        mSignerEcdsaPlain.init(key, Signature.MODE_SIGN);
        return mSignerEcdsaPlain.sign(inputDataBuf, inputDataStart, inputDataLength, sigBuffer,
                sigOffset);
    }

    public short generateSecretEC_SVDP_DHC(byte[] priKey, short priKeyOffset, short priKeySize,
            byte[] pubKey, short pubKeyOffset, short pubKeySize, byte[] secret,
            short secretOffset) {
        if (mKeyAgreement == null) {
            mKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DHC, false);
        }

        ECPrivateKey ecPrivKey = (ECPrivateKey) mEcKeyPair.getPrivate();
        ecPrivKey.setS(priKey, priKeyOffset, priKeySize);

        mKeyAgreement.init(ecPrivKey);
        return mKeyAgreement.generateSecret(pubKey, pubKeyOffset, pubKeySize, secret, secretOffset);
    }

    // X9.63 Key Derivation Function
    public short kdfX963(byte[] shSbuff, short shSOffset, short shSLength, byte[] sharedInfoBuff,
            short sharedInfoOffset, short sharedInfoLen, short keyDataLen, byte[] out,
            short outOffset) {

        MessageDigest.OneShot mDigest = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);
        short hashLen = 0, index = 0;
        byte cnt = 1;
        short initialLength = (short) (shSLength + 4 + sharedInfoLen);

        // TODO: http://www.secg.org/sec1-v2.pdf, page 32
        // Check that |Z| + |SharedInfo| + 4 < hashmaxlen. If |Z| + |SharedInfo| + 4 ≥
        // hashmaxlen,
        // output “invalid” and stop.
        // 2. Check that keydatalen < hashlen × (232 − 1). If keydatalen ≥ hashlen ×
        // (232 − 1), output
        // “invalid” and stop.

        // Add shared secret
        Util.arrayCopyNonAtomic(shSbuff, shSOffset, mInputData, (short) 0, shSLength);
        // Add counter first 3 bytes (as Key count is 5 )
        mInputData[shSLength] = mInputData[(short) (shSLength
                + 1)] = mInputData[(short) (shSLength + 2)] = 0x00;
        // Add Shared info
        Util.arrayCopyNonAtomic(sharedInfoBuff, sharedInfoOffset, mInputData,
                (short) (shSLength + 4), sharedInfoLen);

        try {
            while (index < keyDataLen) {
                mInputData[(short) (shSLength + 3)] = cnt;
                hashLen = mDigest.doFinal(mInputData, (short) 0, initialLength, out,
                        (short) (outOffset + index));

                index += hashLen;
                cnt++;
            }
        } finally {
            if (mDigest != null) {
                mDigest.close();
                mDigest = null;
            }
        }

        return index >= keyDataLen ? keyDataLen : -1;
    }

    // TODO: change the CMAC calculation logic
    //////////////
    private static AESKey setAESkey(byte[] key, short keyOffset, short keyLength) {

        // Keeping only 128 and 256 keys type ONLY
        short lenAESkey = keyLength == (short) 16 ? KeyBuilder.LENGTH_AES_128
                : KeyBuilder.LENGTH_AES_256;

        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, lenAESkey, false);
        aesKey.setKey(key, (short) keyOffset);
        return aesKey;
    }

    public short genCmacAes128(byte[] key, short keyOffset, short keyLength, byte[] inputData,
            short inputDataOffset, short inputDataLength, byte[] out, short outOffset) {
        mMacSignature128.init(setAESkey(key, keyOffset, keyLength), Signature.MODE_SIGN);
        return mMacSignature128.sign(inputData, inputDataOffset, inputDataLength, out, outOffset);
    }

    public short genCmacAes128(byte[] key, short keyOffset, short keyLength, byte[] inputData,
            short inputDataOffset, short inputDataLength, byte[] chainingValue,
            short chainingValueOffset, byte[] out, short outOffset) {
        mMacSignature128.init(setAESkey(key, keyOffset, keyLength), Signature.MODE_SIGN);
        mMacSignature128.update(chainingValue, chainingValueOffset, (short) 16);
        return mMacSignature128.sign(inputData, inputDataOffset, inputDataLength, out, outOffset);
    }

    public boolean verifyCmacAes128(byte[] key, short keyOffset, short keyLength, byte[] inputData,
            short inputDataOffset, short inputDataLength, byte[] sigBuffer, short sigOffset,
            short sigLength) {

        if (mMacSignature128 == null) {
            mMacSignature128 = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        }

        mMacSignature128.init(setAESkey(key, keyOffset, keyLength), Signature.MODE_VERIFY);

        return mMacSignature128.verify(inputData, inputDataOffset, inputDataLength, sigBuffer,
                sigOffset, sigLength);
    }
    //////////////

    // Padding Method 2
    public static short addPaddingM2(byte[] buffer, short offset, short length) {

        // Add the padding constant
        buffer[(short) (offset + (length++))] = (byte) 0x80;

        // Keep adding zeroes until you get to a block length (an empty block will
        // return 1 block)
        while (length < LENGTH_BLOCK_AES || (length % LENGTH_BLOCK_AES != 0)) {
            buffer[(short) (offset + (length++))] = 0x00;
        }

        return length;
    }

    public static short unpadM2(byte[] buffer, short bufferOffset, short bufferLength) {

        if (bufferLength < 1)
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        short offset = (short) (bufferLength - 1);

        while (offset > 0 && buffer[(short) (offset + bufferOffset)] == 0) {
            offset--;
        }

        if (buffer[(short) (offset + bufferOffset)] != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        return offset;
    }

    public short genAes128CbcNopadOutput(byte mode, byte[] keyAes, short keyAesOffset, byte[] iv,
            short ivOffset, short ivLength, byte[] inData, short inDataOffset, short inDataLength,
            byte[] outData, short outDataOffset) {

        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128,
                false);
        key.setKey(keyAes, keyAesOffset);

        mAesCipher.init(key, mode, iv, ivOffset, ivLength);
        // encrypt/decrypt
        return mAesCipher.doFinal(inData, inDataOffset, inDataLength, outData, outDataOffset);
    }

    // TODO: change(combine above) the implementation
    public short genAes128CbcOutput(byte mode, byte[] keyAes, short keyAesOffset, byte[] iv,
            short ivOffset, short ivLength, byte[] inData, short inDataOffset, short inDataLength,
            byte[] outData, short outDataOffset) {

        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128,
                false);
        key.setKey(keyAes, keyAesOffset);

        mAesCipherT.init(key, mode, iv, ivOffset, ivLength);

        // encrypt/decrypt
        return mAesCipherT.doFinal(inData, inDataOffset, inDataLength, outData, outDataOffset);
    }

    // TODO: Change/merge the following functions

    // KDF in counter mode as specified in NIST SP 800-108 ([NIST 800-108]). The PRF
    // used in the KDF shall be CMAC as specified in [NIST 800-38B], used with full
    // 16-byte output length.
    // Referred from SCP03_v1.1.2_PublicRelease for input data collection
    public short cmacKdfCounterMode(byte[] key, short keyOffset, byte[] label, short labelStart,
            short labelLen, byte[] L, short Loffset, short Llength, byte counter, byte[] context,
            short contextStart, short contextLength, byte[] outData, short outDataOffset) {

        byte i = 1;
        short pos = 0;

        // Create an AES key
        AESKey aeskey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128,
                false);
        aeskey.setKey(key, (short) keyOffset);
        mMacSignature128.init(aeskey, Signature.MODE_SIGN);

        // ZERO byte (1 byte separation) 
        mInputData[0] = 0x00;

        while (i <= counter) {
            mMacSignature128.update(label, labelStart, (short) labelLen);  // label
            mMacSignature128.update(mInputData, (short) 0, (short) 1);     // 1 byte separation
                                                                           // indicator
            mMacSignature128.update(L, Loffset, Llength); // L

            mInputData[1] = i;
            mMacSignature128.update(mInputData, (short) 1, (short) 1);      // counter
            mMacSignature128.update(context, contextStart, contextLength);  // context

            // signature of 16 bytes
            pos = mMacSignature128.sign(L, (short) Loffset, (short) Llength, outData,
                    (short) (outDataOffset + pos));
            i++;
        }
        return pos;
    }

    public short cmacKdfCounterModeFiRa2(byte[] key, short keyOffset, byte label1, byte label2,
            byte[] outData, short outDataOffset) {

        short inLen = 0;

        // Create an AES key
        AESKey aeskey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128,
                false);
        aeskey.setKey(key, (short) keyOffset);
        mMacSignature128.init(aeskey, Signature.MODE_SIGN);

        // Note it(input) allows defining a different order than proposed by standard as
        // long as
        // it is unambiguously defined.
        // 2 bytes label, distinguishing the purpose of the key
        // 2 bytes counter, always set to 0x0001 as only 128 bits keys are generated
        // 2 bytes length, always set to 0x0080 as only 128 bits keys are generated
        // 10 bytes context, set all to 0x00
        mInputData[inLen++] = label1;
        mInputData[inLen++] = label2;
        mInputData[inLen++] = 0x00;
        mInputData[inLen++] = 0x01;
        mInputData[inLen++] = 0x00;
        mInputData[inLen++] = (byte) 0x80;
        Util.arrayFillNonAtomic(mInputData, inLen, (short) 10, (byte) 0x00);
        inLen += 10;

        return mMacSignature128.sign(mInputData, (short) 0, inLen, outData, outDataOffset);
    }

    // AES_CMAC(UWB ranging root key, derivation data) where:
    // o Derivation data = Counter (32b) | Label | Diversification data | Length
    // (32b)
    // o Derivation data length shall be provisioned to be 128 or 256 bits long
    // o UWB ranging root key is provisioned in the ADF (see 8.2.2.14.1.2). It shall
    // be either 128 or
    // 256 bits long. Length of derived key will be same as UWB ranging root key
    // o Label is provisioned in the ADF
    // o Diversification data is the value taken from the UWB_SESSION_KEY_INFO
    // object
    // § Diversification data length shall be such that total length or derivation
    // data is 128 or
    // 256 bits as set during provisioning. If Diversification data is too short,
    // 0x0 shall be
    // inserted to the left to reach diversification data length. If it is too long,
    // only the leftmost
    // bytes shall be kept.
    // § For instance, assuming a length of 128 bits for derivation data and a label
    // length of 32
    // bits, diversification data shall be 128 – 32 (counter) – 32 (label) – 32
    // (length) = 32
    // bits, if UWB_SESSION_KEY_INFO is set to 0x67, then diversification data shall
    // be
    // extended to 0x00000067. If UWB_SESSION_KEY_INFO is set to
    // 0x0123456789abcdef, diversification data shall be set to 0x01234567.
    // o If 256 bits (resp 128 bits) key is provisioned, Length used in derivation
    // shall be 0x00000100
    // (resp. 0x00000080) and counter shall take successive values of 0x00000001 and
    // 0x00000002 (resp. only 0x00000001) during key derivation
    public short cmacKdfCounterModeUWBsessionKey(byte[] key, short keyOffset, short keyLength,
            byte[] label, short labelStart, short labelLen, byte[] diversification,
            short diversificationOffset, short diversificationLength, byte[] outData,
            short outDataOffset) {

        byte i = 1;
        short pos = 0;
        byte counter = (keyLength == (short) 16) ? (byte) 0x01 : (byte) 0x02;

        mMacSignature128.init(setAESkey(key, keyOffset, keyLength), Signature.MODE_SIGN);

        Util.arrayFillNonAtomic(mInputData, (short) 0, (short) 28, (byte) 0x00);
        if (keyLength == (short) 16) {
            mInputData[7] = (byte) 0x80;
        } else {
            mInputData[6] = (byte) 0x01;
        }

        while (i <= counter) {
            mInputData[3] = i;
            mMacSignature128.update(mInputData, (short) 0, (short) 4);    // counter
            mMacSignature128.update(label, labelStart, (short) labelLen); // label

            if (diversificationLength >= (keyLength == (short) 16 ? (short) 4 : (short) 20)) {
                // Diversification Data
                mMacSignature128.update(diversification, diversificationOffset,
                        diversificationLength);
            } else {
                mMacSignature128.update(mInputData, (short) 8,
                        (short) ((keyLength == (short) 16 ? (short) 4 : (short) 20)
                                - diversificationLength));
                // Diversification Data
                mMacSignature128.update(diversification, diversificationOffset,
                        diversificationLength);
            }

            // signature of 16 bytes
            pos = mMacSignature128.sign(mInputData, (short) 4, (short) 4, outData,
                    (short) (outDataOffset + pos)); // L
            i++;
        }

        return pos;
    }
}
