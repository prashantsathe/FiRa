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
import javacardx.crypto.Cipher;

public class Scp3Lib {
    // SCP 03 variables
    private byte[] mChainingValue;
    private byte[] mS_ENC;
    private byte[] mS_MAC;
    private byte[] mS_RMAC;
    private byte[] mS_DEK;
    private byte[] mS_KEY_SIZE;
    private byte[] mEncryptionCounter;
    private byte[] mEncryptionCounterResponse;
    public static byte[] mNullBytes16;
    private static byte[] mInData;
    private static byte[] mOutData;

    private Crypto mCrypto;

    private void Scp3LibInit() {
        mChainingValue = JCSystem.makeTransientByteArray(BLOCK16, JCSystem.CLEAR_ON_RESET);
        mS_ENC = JCSystem.makeTransientByteArray(SC_SECRETE_LENGTH, JCSystem.CLEAR_ON_RESET);
        mS_MAC = JCSystem.makeTransientByteArray(SC_SECRETE_LENGTH, JCSystem.CLEAR_ON_RESET);
        mS_RMAC = JCSystem.makeTransientByteArray(SC_SECRETE_LENGTH, JCSystem.CLEAR_ON_RESET);
        mS_DEK = JCSystem.makeTransientByteArray(SC_SECRETE_LENGTH, JCSystem.CLEAR_ON_RESET);
        mS_KEY_SIZE = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mEncryptionCounter = JCSystem.makeTransientByteArray(BLOCK16, JCSystem.CLEAR_ON_RESET);
        mEncryptionCounterResponse = JCSystem.makeTransientByteArray(BLOCK16, JCSystem.CLEAR_ON_RESET);
        InitStaticFields();
    }

    private void InitStaticFields() {
        // Check just one field for NULL
        if (mInData == null) {
            mNullBytes16 = JCSystem.makeTransientByteArray(BLOCK16, JCSystem.CLEAR_ON_RESET);
            mInData = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_RESET);
            mOutData = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_RESET);
        }
    }

    public Scp3Lib() {

        if (mCrypto == null)
            mCrypto = new Crypto();

        Scp3LibInit();
    }

    public Scp3Lib(Crypto crypto) {
        mCrypto = crypto;
        Scp3LibInit();
    }

    private static void bufferIncrement(byte[] buffer, short offset, short len) {

        if (len < 1)
            return;

        for (short i = (short) (offset + len - 1); i >= offset; i--) {
            if (buffer[i] != (byte) 0xFF) {
                buffer[i]++;
                break;
            } else
                buffer[i] = (byte) 0x00;
        }
    }

    private static short getUnpadOffset(byte[] buffer, short offsetbuff, short len) {
        short offset = (short) (len - 1);

        while (((short)(offset + offsetbuff) > offsetbuff) && buffer[(short) (offsetbuff + offset)] == 0x00) {
            offset--;
        }

        if (buffer[(short) (offsetbuff + offset)] != (byte) 0x80) {
            // TODO : Invalid ISO 7816-4 padding exception
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        return offset;
    }

    private static short pad80(byte[] buffer, short bufOffset, short bufLen, short blocksize) {
        short total = (short) ((bufLen / blocksize + 1) * blocksize);
        short cnt = bufLen;
        buffer[(short) (bufOffset + cnt)] = (byte) 0x80;

        while (++cnt < total) {
            buffer[(short) (bufOffset + cnt)] = 0x00;
        }
        return total;
    }

    /**
     * Set derived keys of SCP03 protocol
     *
     * @param keyBuff : input key buffer
     * @param keyBuffOffset : start index of 'inputData'
     * @param keyLen : size of individual key
     */
    public void setKeys(byte[] keyBuff, short keyBuffOffset, byte keyLen) {
        Util.arrayCopyNonAtomic(keyBuff, (short) keyBuffOffset, mS_ENC, (short) 0, (short) keyLen);
        Util.arrayCopyNonAtomic(keyBuff, (short) (keyBuffOffset + keyLen), mS_MAC, (short) 0, (short) keyLen);
        Util.arrayCopyNonAtomic(keyBuff, (short) (keyBuffOffset + (keyLen * 2)), mS_RMAC, (short) 0, (short) keyLen);
        Util.arrayCopyNonAtomic(keyBuff, (short) (keyBuffOffset + (keyLen * 3)), mS_DEK, (short) 0, (short) keyLen);

        // // default Secure keys testing
        // Util.arrayFillNonAtomic(mS_ENC, (short) 0, (short) 32, (byte) 0x04);
        // Util.arrayFillNonAtomic(mS_MAC, (short) 0, (short) 32, (byte) 0x04);
        // Util.arrayFillNonAtomic(mS_RMAC, (short) 0, (short) 32, (byte) 0x04);
        mS_KEY_SIZE[0] = keyLen;
    }

    /**
     * Get encryption derived key buffer
     *
     * @return encrypt-derived key buffer
     */
    public byte[] getSEncKey() {
        return mS_ENC;
    }

    /**
     * Reset scp03 context (secret keys)
     */
    public void reset() {
        Util.arrayFillNonAtomic(mS_ENC, (short) 0, SC_SECRETE_LENGTH, (byte) 0x00);
        Util.arrayFillNonAtomic(mS_MAC, (short) 0, SC_SECRETE_LENGTH, (byte) 0x00);
        Util.arrayFillNonAtomic(mS_RMAC, (short) 0, SC_SECRETE_LENGTH, (byte) 0x00);
        Util.arrayFillNonAtomic(mS_DEK, (short) 0, SC_SECRETE_LENGTH, (byte) 0x00);
    }

    /**
     *
     * @param inputData
     * @param inputDataOffset
     * @param inputDataLength
     * @param out
     * @param outOffset
     * @return
     */
    public short genCmac(byte[] inputData, short inputDataOffset, short inputDataLength, byte[] out,
                         short outOffset) {

        short len = mCrypto.genCmacAes128(mS_MAC, (short) 0, mS_KEY_SIZE[0], inputData, inputDataOffset,
                inputDataLength, mChainingValue, (short) 0, out, outOffset);

        // set new chaining value (C-MAC of last calculation) / Check if need to change the chaining 
        // value in case of failure(!=16)
        Util.arrayCopyNonAtomic(out, outOffset, mChainingValue, (short) 0, BLOCK16);
        return len;
    }

    private boolean verifyMac(byte securityLevel, byte[] buff, short buffOffset, short buffLen,
            boolean resApdu) {

        // NOTE: if securityLevel is not set to desired MAC, return true
        // And the Secure channel shall support a MAC of 8 bytes length (even if the AES block
        // length is 16 bytes). Hence the eight most significant bytes are considered.
        if (resApdu) {
            if ((securityLevel & R_MAC) == R_MAC) {
                // Compare R-Mac. copy data and status in mInData
                Util.arrayCopyNonAtomic(buff, buffOffset, mInData, (short) 0,
                        (short) (buffLen - 10 /* 8 MAC + 2 Status*/));
                Util.arrayCopyNonAtomic(buff, (short) (buffOffset + buffLen - 10),
                        mInData, (short) (buffLen - 10), (short) 8);

                if (mCrypto.genCmacAes128(mS_RMAC, (short) 0, mS_KEY_SIZE[0], mInData, (short) 0,
                        (short) (buffLen - 8), mChainingValue, (short) 0, mOutData, (short) 0)
                        != BLOCK16 || Util.arrayCompare(mOutData, (short) 0, buff, 
                                (short) (buffOffset + buffLen - 8), (short) 8) != (byte) 0x00) {
                        return false;
                }
            }
        } else {
            // Compare CMAC
            if ((securityLevel & C_MAC) == C_MAC)
                if (genCmac(buff, buffOffset, (short) (buffLen - 8), mOutData, (short) 0)
                        != BLOCK16 || Util.arrayCompare(mOutData, (short) 0, buff,
                                (short) (buffOffset + buffLen - 8), (short) 8) != (byte) 0x00) {
                    return false;
                }
        }

        return true;
    }

    // data gets stored at 'mOutData' at 0 offset
    private short encryptIV(boolean resApdu) {

        if (resApdu) {
            Util.arrayCopyNonAtomic(mEncryptionCounter, (short) 1, mEncryptionCounterResponse,
                    (short) 1, (short) 15);
            mEncryptionCounterResponse[0] = (byte) 0x80;
        } else {
            bufferIncrement(mEncryptionCounter, (short) 0, (short) 16);
        }
        // encrypt IV
        return mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mS_ENC, (short) 0,
                mNullBytes16, (short) 0, BLOCK16, resApdu ? mEncryptionCounterResponse : mEncryptionCounter,
                (short) 0, (short) 16, mOutData, (short) 0);
    }

    private short decryptData(byte securityLevel, byte[] buff, short buffOffset, short buffLen, boolean resApdu) {
        short outLen = 0;
        short cdOffset = (short) (buff[(short) (buffOffset + ISO7816.OFFSET_CDATA)] == (byte) 0x00 ? 7 : 5);
        short cdLength = (short) (buffLen - cdOffset);

        if (resApdu) {
            if ((securityLevel & R_ENCRYPTION) == R_ENCRYPTION) {
                // encrypt IV, data is stored in mOutData at 0
                outLen = encryptIV(resApdu);

                // Decrypt the data
                // NOTE: size greater than 8+2 is already checked in verifyMac()
                short dataLen = (short) (buffLen - 10);
                Util.arrayCopyNonAtomic(buff, buffOffset, mInData, (short) 0, dataLen);
                dataLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, mS_ENC, (short) 0,
                                        mOutData, (short) 0, outLen, mInData, (short) 0, dataLen,
                                        mOutData, outLen);
                Util.arrayCopyNonAtomic(mOutData, outLen, buff, buffOffset,  dataLen);
                outLen = dataLen;
            } else {
                outLen = (short) ((securityLevel & R_MAC) == R_MAC ? buffLen - 8 : buffLen);
            }
        } else {
            if ((securityLevel & C_DECRYPTION) == C_DECRYPTION) {
                short bufferCdOffset = (short) (buffOffset + cdOffset);

                // encrypt IV, data is stored in mOutData at 0
                outLen = encryptIV(resApdu);
                // decrypt the data
                outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, mS_ENC, (short) 0,
                        mOutData, (short) 0, outLen, buff, bufferCdOffset, (short) (cdLength - 8),
                        mInData, (short) 0); // copy decrypted data in mInData

                outLen = getUnpadOffset(mInData, (short) 0, outLen); // offSet80

                // copy data to buffer
                // Supporting only extended length
                cdOffset = (short) 7;
                buff[(short) (bufferCdOffset - 3)] = (byte) 0x00;
                Util.setShort(buff, (short) (bufferCdOffset - 2), outLen);
                Util.arrayCopyNonAtomic(mInData, (short) 0, buff, bufferCdOffset, outLen);

                // return value should be cdOffset + outLen
                outLen += cdOffset;
            } else {
                outLen = (short) ((securityLevel & C_MAC) == C_MAC ? buffLen - 8 : buffLen);
            }
        }

        return outLen;
    }

    /**
     * unwrap(de-encrypt) incoming 'buff' start from 'buffOffset' based on 'securityLevel' argument
     * having length 'buffLen' and decrypt the data in buff from 'buffOffset'
     *
     * @param securityLevel : security level for encryption/wrapping
     * @param buff : incoming buffer array where unwrapped data is stored
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     * @param resApdu : true when response apdu else false for command apdu
     *
     * @return length of unwrapped data stored in 'buff' starting from 'buffOffset'
     */
    public short unwrap(byte securityLevel, byte[] buff, short buffOffset, short buffLen,
            boolean resApdu) {

        // First check incoming size
        if (buffLen <= 2) return buffLen;
        if (((securityLevel & R_MAC) == R_MAC || (securityLevel & C_MAC) == C_MAC)
                && buffLen < 10) {
            return 0;
        }

        // Second verify MAC
        if (!verifyMac(securityLevel, buff, buffOffset, buffLen, resApdu))
            return 0;

        // Third decrypt the data
        return decryptData(securityLevel, buff, buffOffset, buffLen, resApdu);
    }

    private short wrapCommand(byte securityLevel, byte[] buff, short buffOffset, short buffLen) {
        short outLen = 0, outOffset = 0;
        short cdOffset = ISO7816.OFFSET_CDATA, cdLength = 0;
        boolean cipheredData = false;

        if (buffLen <= ISO7816.OFFSET_LC)
            return buffLen;
        if (buffLen > ISO7816.OFFSET_CDATA && (buff[ (short) (buffOffset + ISO7816.OFFSET_LC)] == 0))
            cdOffset = (short) 7;

        cdLength = (short) (cdOffset == (short) 5 ? buff[(short) (buffOffset + ISO7816.OFFSET_LC)] :
            Util.getShort(buff, (short) (buffOffset + ISO7816.OFFSET_LC + 1)));

        // First: Encrypt data if bufLen > 0 & C_DECRYPTION, based on
        // 'GPC_2.3_D_SCP03_v1.1.2_PublicRelease.pdf' figure 6-4
        if ((securityLevel & C_DECRYPTION) == C_DECRYPTION) {
            // encrypt the IV, data is stored in mOutData at 0
            outLen = encryptIV(false);

            // Encrypt the data
            Util.arrayCopyNonAtomic(buff, (short) (buffOffset + cdOffset), mInData, (short) 0,
                    cdLength);
            short totalLenWithpad = pad80(mInData, (short) 0, cdLength, BLOCK16); // 16 is a block size
            outOffset = outLen;
            outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mS_ENC, (short) 0,
                    mOutData, (short) 0,outLen, mInData, (short) 0, totalLenWithpad, mOutData,
                    outOffset);
            cipheredData = true;
        }

        // Second: calculate MAC
        if ((securityLevel & C_MAC) == C_MAC) {
            // copy CLA/INS/p1/p2
            Util.arrayCopyNonAtomic(buff, buffOffset, mInData, (short) 0, (short) 4);
            // only support extended length
            mInData[4] = 0x00;

            if (cipheredData) {
                // ciphered data
                Util.setShort(mInData, (short) 5, (short) (outLen + 8)); // LCC = lc + 8
                Util.arrayCopyNonAtomic(mOutData, outOffset, mInData, (short) 7, outLen);
            } else {
                outLen = cdLength;
                Util.setShort(mInData, (short) 5, (short) (outLen + 8)); // LCC = lc + 8
                Util.arrayCopyNonAtomic(buff, (short) (buffOffset + cdOffset), mInData, (short) 7,
                        outLen);
            }
            outLen += 7;

            if (genCmac(mInData, (short) 0, outLen, mOutData, (short) 0) != BLOCK16) {
                return 0;
            }

            Util.arrayCopyNonAtomic(mInData, (short) 0, buff, buffOffset, outLen);
            // The Secure channel shall support a MAC of 8 bytes length (even if the AES block
            // length is 16 bytes). Hence the eight most significant bytes are considered.
            Util.arrayCopyNonAtomic(mOutData, (short) 0, buff, (short) (buffOffset + outLen),
                    (short) 8);
            outLen += 8;
        } else {
            if (cipheredData) {
                // ciphered data
                Util.arrayCopyNonAtomic(mOutData, outOffset, buff, buffOffset, outLen);
            } else {
                return buffLen;
            }
        }

        return outLen;
    }

    private short wrapResponse(byte securityLevel, byte[] buff, short buffOffset, short buffLen) {
        short outLen = 0, outOffset = 0;
        boolean cipheredData = false;

        // First: Encrypt data if buffLen > 2 & R_ENCRYPTION based on 'GPC_2.3_D_SCP03_v1.1.2_PublicRelease.pdf'
        // figure 6-5
        if (((securityLevel & R_ENCRYPTION) == R_ENCRYPTION) && (buffLen > 2 /*status*/)) {
            // encrypt the IV, data is stored in mOutData at 0
            outLen = encryptIV(true);

            // Encrypt the data
            Util.arrayCopyNonAtomic(buff, buffOffset, mInData, (short) 0, (short) (buffLen - 2));
            short totalLenWithpad = pad80(mInData, (short) 0, (short) (buffLen - 2), BLOCK16); // 16 is a block size
            outOffset = outLen;
            outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mS_ENC, (short) 0,
                                    mOutData, (short) 0, outLen, mInData, (short) 0, totalLenWithpad,
                                    mOutData, outOffset);
            cipheredData = true;
        }

        if ((securityLevel & R_MAC) == R_MAC && (buffLen > 2 /*status*/)) {
            // Second: calculate MAC
            if (cipheredData) {
                Util.arrayCopyNonAtomic(mOutData, outOffset, mInData, (short) 0, outLen); // ciphered data
            } else {
                Util.arrayCopyNonAtomic(buff, buffOffset, mInData, (short) 0, buffLen); // un-ciphered data
                outLen = buffLen;
            }

            Util.arrayCopyNonAtomic(buff, (short) (buffOffset + buffLen - 2), mInData,
                                    outLen, (short) 2); // copy status
            outLen += 2;

            if (mCrypto.genCmacAes128(mS_RMAC, (short) 0, mS_KEY_SIZE[0], mInData, (short) 0,
                    outLen, mChainingValue, (short) 0, mOutData, (short) 0) != BLOCK16) {
                    return 0;
            }

            outLen -= 2;
            Util.arrayCopyNonAtomic(mInData, (short) 0, buff, buffOffset, outLen);
            // The Secure channel shall support a MAC of 8 bytes length (even if the AES block length is 16 bytes).
            // Hence the eight most significant bytes are considered.
            Util.arrayCopyNonAtomic(mOutData, (short) 0, buff, (short) (buffOffset + outLen), (short) 8);
            outLen += 8;
        } else {
            if (cipheredData)
                Util.arrayCopyNonAtomic(mOutData, outOffset, buff, buffOffset, outLen); // ciphered data
            else
                outLen = buffLen;
        }

        return outLen;
    }

    /**
     * Wrap(encrypt) incoming 'buff' start from 'buffOffset' based on 'securityLevel' argument
     * having length 'buffLen'
     *
     * @param securityLevel : security level for encryption/wrapping
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     * @param resApdu : true when response apdu else false for command apdu
     *
     * @return length of wrapped data in 'buff' starting from 'buffOffset'
     */
    public short wrap(byte securityLevel, byte[] buff, short buffOffset, short buffLen, boolean resApdu) {

        if (resApdu) {
            return wrapResponse(securityLevel, buff, buffOffset, buffLen);
        }
        // else wrap command
        return wrapCommand(securityLevel, buff, buffOffset, buffLen);
    }

    /**
     * key derivation function based on scp03 protocol (SCP03_v1.1.2_PublicRelease) and fiRa (CSML - 7.5.3.3.1)
     * based on argument 'uwbSessionKeyFlag'
     *
     * @param keyBuff : key buffer for cmac
     * @param keyOffset : offset of key buffer
     * @param context : context buffer
     * @param contextOffset : offset of context buffer
     * @param contextLength : context length
     * @param deviationConstant : derivation constant for CMAC
     * @param uwbSessionKeyFlag : used when KDF is calculated for FiRa
     * @param outData : output data buffer where KDF is stored
     * @param outDataOffset : output buffer offset
     *
     * @return length of KDF data, if successful
     */
    public short scp03KDF(byte[] keyBuff, short keyBuffOffset, byte[] contextBuff, short contextBuffOffset,
            short contextBuffLength, byte deviationConstant, boolean uwbSessionKeyFlag, byte[] outData,
            short outDataOffset) {

        // 1. section 6.2.2 - Challenges and Authentication Cryptograms (SCP03_v1.1.2_PublicRelease)
        // 2. CSML - 7.5.3.3.1 Default UWB Session Key and UWB Session ID
        // label
        Util.arrayFillNonAtomic(mInData, (short) 0, uwbSessionKeyFlag ? (short) 7 : (short) 11, (byte) 0x00);

        if (uwbSessionKeyFlag) {
            // 0x46 0x49 0x52 0x41 (FIRA in hex)
            mInData[7] = (byte) 0x46;
            mInData[8] = (byte) 0x49;
            mInData[9] = (byte) 0x52;
            mInData[10] = (byte) 0x41;
        }

        mInData[11] = deviationConstant;

        // L
        mInData[12] = 0x00;
        mInData[13] = 0x40;

        return mCrypto.cmacKdfCounterMode(keyBuff, keyBuffOffset, mInData, (short) 0, (short) 12, mInData, (short) 12,
                (short) 2, (byte) 0x01, contextBuff, contextBuffOffset, contextBuffLength, outData, outDataOffset);
    }
}
