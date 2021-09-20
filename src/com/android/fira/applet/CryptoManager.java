package com.android.fira.applet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

public class CryptoManager {

    private final Cipher mAesCipher;
    private final AESKey mAesKey;

    // Storage key for a credential
    private final byte[] mRandomStorageKey;
    // Random data generator
    private final RandomData mRandomData;

    protected CryptoManager() {
        // AES for encrypting-decrypting ADF
        mAesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        mAesKey = (AESKey) KeyBuilder.buildKey(
                                KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        // Create the storage key byte array
        mRandomStorageKey = JCSystem.makeTransientByteArray(Constant.AES_KEY_SIZE, JCSystem.CLEAR_ON_RESET);
        mRandomData = RandomData.getInstance(RandomData.ALG_TRNG);

        // create Credential Storage Key & Set Key
        mRandomData.nextBytes(mRandomStorageKey, (short) 0, Constant.AES_KEY_SIZE);

        // Set AES key
        mAesKey.setKey(mRandomStorageKey, (short) 0);
    }

    public short aesCBC128NoPadEncrypt(byte[] data, short dataStart, short dataLen,
                               byte[] encData, short encDataStart) {
        // check for input data in AES_BLOCK_SIZE
        if ((dataLen % Constant.AES_BLOCK_SIZE) !=0) {
            return 0;
        }

        mAesCipher.init(mAesKey, Cipher.MODE_ENCRYPT);
        return mAesCipher.doFinal(data, dataStart, dataLen, encData, encDataStart);
    }

    public short aesCBC128NoPadDecrypt(byte[] data, short dataStart, short dataLen,
                               byte[] encData, short encDataStart ) {

        mAesCipher.init(mAesKey, Cipher.MODE_DECRYPT);
        return mAesCipher.doFinal(data, dataStart, dataLen, encData, encDataStart);
    }
}
