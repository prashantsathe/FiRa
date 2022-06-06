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
    public byte[] mNullBytes16;
    private byte[] mInData;
    private byte[] mOutData;

    private Crypto mCrypto;

    private void Scp3LibInit() {
        mChainingValue = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
        mS_ENC = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
        mS_MAC = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
        mS_RMAC = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
        mS_DEK = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
        mS_KEY_SIZE = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mEncryptionCounter = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
        mEncryptionCounterResponse = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
        mNullBytes16 = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
        Util.arrayFill(mNullBytes16, (short)0, (short)16, (byte) 0x00);
        mInData = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_RESET);
        mOutData = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_RESET);
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
        Util.arrayCopyNonAtomic(out, outOffset, mChainingValue, (short) 0, (short) 16);
        return len;
    }

    /**
     * unwrap(de-encrypt) incoming 'buff' start from 'buffOffset' based on 'securityLevel' argument
     * having length 'buffLen' and uncrypted data in buff from 'buffOffset'
     *
     * @param securityLevel : security level for encryption/wrapping
     * @param buff : incoming buffer array where unwrapped data is stored
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     *
     * @return length of unwrapped data stored in 'buff' starting from 'buffOffset'
     */
    public short unwrap(byte securityLevel, byte[] buff, short buffOffset, short buffLen) {
        short outLen = 0, offSet80 = 0;
        short cdOffset = (short) (buff[(short) (buffOffset + ISO7816.OFFSET_CDATA)] == (byte) 0x00 ? 7 : 5);
        short cdLength = (short) (buffLen - cdOffset);

        if ((securityLevel & C_MAC) == C_MAC) {
            // First: Compare CMAC
            if (genCmac(buff, buffOffset, (short) (buffLen - 8), mOutData, (short) 0) != 16 ||
                Util.arrayCompare(mOutData, (short) 0, buff, (short) (buffLen - 8),
                        (short) 8) != (byte) 0x00) {
                return 0;
            }
        }

        // Second: decrypt the data
        if ((securityLevel & C_DECRYPTION) == C_DECRYPTION) {
            // get encrypted IV
            bufferIncrement(mEncryptionCounter, (short) 0, (short) 16);
            outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mS_ENC, (short) 0,
                    mNullBytes16, (short) 0, (short) 16, mEncryptionCounter, (short) 0, (short) 16,
                    mOutData, (short) 0);

            outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_DECRYPT, mS_ENC, (short) 0,
                    mOutData, (short) 0, outLen, buff, cdOffset, (short) (cdLength - 8),
                    mInData, (short) 0); // copy decrypted data in mInData

            // copy data to buffer
            offSet80 = getUnpadOffset(mInData, (short) 0, outLen);

            if (offSet80 > (short) 255) {
                cdOffset = (short) 7;
                buff[(short) (buffOffset + cdOffset - 3)] = (byte) 0x00;
                Util.setShort(buff, (short) (buffOffset + cdOffset - 2), offSet80);
            } else {
                cdOffset = (short) 5;
                buff[(short) (buffOffset + cdOffset - 1)] = (byte) (offSet80);
            }
            Util.arrayCopyNonAtomic(mInData, (short) 0, buff, cdOffset, offSet80);
        }

        return offSet80;
    }

    /**
     * Wrap(encrypt) incoming 'buff' start from 'buffOffset' based on 'securityLevel' argument
     * having length 'buffLen'
     *
     * @param securityLevel : security level for encryption/wrapping
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     *
     * @return length of wrapped data in 'buff' starting from 'buffOffset'
     */
    public short wrap(byte securityLevel, byte[] buff, short buffOffset, short buffLen) {

        short outLen = 0, outOffset = 0;
        boolean cipheredData = true;

        // First: Encrypt data if bufLen > 0 & R_ENCRYPTION
        if (((securityLevel & R_ENCRYPTION) == R_ENCRYPTION) && (buffLen > 0)) {
            // encrypt IV
            Util.arrayCopyNonAtomic(mEncryptionCounter, (short) 1, mEncryptionCounterResponse,
                    (short) 1, (short) 15);
            mEncryptionCounterResponse[0] = (byte) 0x80;

            outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mS_ENC, (short) 0,
                    mNullBytes16, (short) 0, (short) 16, mEncryptionCounterResponse,
                    (short) 0, (short) 16, mOutData, (short) 0);

            // Encrypt the data
            Util.arrayCopyNonAtomic(buff, buffOffset, mInData, (short) 0, (short) (buffLen - 2));
            short totalLenWithpad = pad80(mInData, (short) 0, (short) (buffLen - 2), (short) 16); // 16 is a block size
            outOffset = outLen;
            outLen = mCrypto.genAes128CbcNopadOutput(Cipher.MODE_ENCRYPT, mS_ENC, (short) 0,
                                    mOutData, (short) 0, outLen, mInData, (short) 0, totalLenWithpad,
                                    mOutData, outOffset);
        } else if (buffLen > 0) {
            cipheredData = false;
        }

        if ((securityLevel & R_MAC) == R_MAC) {
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
                    outLen, mChainingValue, (short) 0, mOutData, (short) 0) != (short) 16) {
                    return 0;
            }

            outLen -= 2;
            Util.arrayCopyNonAtomic(mInData, (short) 0, buff, buffOffset, outLen);
            Util.arrayCopyNonAtomic(mOutData, (short) 0, buff, (short) (buffOffset + outLen), (short) 8);
            outLen += 8;
        } else {
            if (cipheredData)
                Util.arrayCopyNonAtomic(mOutData, outOffset, buff, buffOffset, outLen); // ciphered data
            else
                return buffLen;
        }

        return outLen;
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
    public short scp03KDF(byte[] keyBuff, short keyBuffOffset, byte[] contextBuff, short contextBuffOffset, short contextBuffLength,
                          byte deviationConstant, boolean uwbSessionKeyFlag, byte[] outData, short outDataOffset) {

        // 1. section 6.2.2 - Challenges and Authentication Cryptograms (SCP03_v1.1.2_PublicRelease)
        // 2. CSML - 7.5.3.3.1 Default UWB Session Key and UWB Session ID
        // label
        Util.arrayFill(mInData, (short) 0, uwbSessionKeyFlag ? (short) 7 : (short) 11, (byte) 0x00);

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

        return mCrypto.cmacKdfCounterMode(keyBuff, keyBuffOffset, mInData, (short) 0, (short) 12,
                mInData, (short) 12, (short) 2, (byte) 0x01, contextBuff, contextBuffOffset, contextBuffLength,
                outData, outDataOffset);
    }
}
