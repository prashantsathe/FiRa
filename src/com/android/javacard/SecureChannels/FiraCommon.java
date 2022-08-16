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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class FiraCommon {

    private FiraContext mContext;
    private Crypto mCrypto;
    private Scp3Lib mScp3Lib;

    public FiraCommon(FiraContext context, Crypto crypto, Scp3Lib scp3Lib) {
        mContext = context;
        mCrypto = crypto;
        mScp3Lib = scp3Lib;
    }

    public void generateDefaultUWBKeys(byte[] keyBuff, short keyBuffOffset, byte[] context,
            short contextOffset, short contextLength, byte deviationConstant,
            boolean uwbSessionKeyFlag) {
        // generate and set UWB default key and session ID
        // The default values for both UWB Session Key and UWB Session ID shall be calculated
        // according to GPC_2.3_D_SCP03_v1.2:April 2020 [17] section 4.1.5, using the S-MAC as root
        // key. "As mUWBsessionID is 4 bytes storing mUWBsessionID in mUWBsessionKey temporarily"
        if (mScp3Lib.scp03KDF(keyBuff, keyBuffOffset, context, contextOffset,
                contextLength, deviationConstant, uwbSessionKeyFlag, mContext.mBuf,
                O_UWB_SESSIONKEY) != SIGNATURE_BLOCK_SIZE ||
            Util.arrayCopyNonAtomic(mContext.mBuf, O_UWB_SESSIONKEY, mContext.mBuf,
                    O_UWB_SESSIONID, UWB_SESSION_ID_SIZE) !=
                    (short) (UWB_SESSION_ID_SIZE + O_UWB_SESSIONID) ||
            mScp3Lib.scp03KDF(keyBuff, keyBuffOffset, context, contextOffset,
                    contextLength, deviationConstant, uwbSessionKeyFlag, mContext.mBuf,
                    O_UWB_SESSIONKEY) != SIGNATURE_BLOCK_SIZE) {
            // Crypto error
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    // 7.2.1.4.2 Derivation of the Secure Messaging Session Keys
    // KSENC = PRF(KENC, 0x00000000000000000000000400008001 ║ K.IFD ║ K.ICC)
    // KSMAC = PRF(KMAC, 0x00000000000000000000000600008001 ║ K.IFD ║ K.ICC)
    // pretext must be "0x000000000000000000000000 000080"
    public void setScpAndUWBsessionKey(byte[] preText, short preTextOffset, byte[] kIfdIccBuffer,
            short kIfdIccBufferOffset, short kIfdIccBufferLength, byte[] keyBuff, short encKeyOffset,
            short macKeyOffset, byte[] outData, short outDataOffset) {

        preText[(short) (preTextOffset + 11)] = (byte) 0x04;
        short keyLength = mCrypto.cmacKdfCounterMode(keyBuff, encKeyOffset, preText, preTextOffset,
                (short) 12, preText, (short) (preTextOffset + 12), (short) 3, (byte) 0x01,
                kIfdIccBuffer, kIfdIccBufferOffset, kIfdIccBufferLength, outData,
                outDataOffset);

        preText[(short) (preTextOffset + 11)] = (byte) 0x06;
        keyLength = mCrypto.cmacKdfCounterMode(keyBuff, macKeyOffset, preText, preTextOffset,
                (short) 12, preText, (short) (preTextOffset + 12), (short) 3, (byte) 0x01,
                kIfdIccBuffer, kIfdIccBufferOffset, kIfdIccBufferLength, outData,
                (short) (keyLength + outDataOffset));

        // NOTE: Here we use scp03 class for secure channel data wrapping where RMAC and SMAC are
        //       same and we are setting secure channel level as CDECMAC_RENCMAC
        setSecurityLevel(CDECMAC_RENCMAC);
        Util.arrayCopyNonAtomic(outData, (short) (keyLength + outDataOffset), outData,
                (short) ((keyLength * 2) + outDataOffset), keyLength);
        mScp3Lib.setKeys(outData, outDataOffset, (byte) keyLength);

        // generate and set UWB default key and session ID
        generateDefaultUWBKeys(outData, (short) (keyLength + outDataOffset), kIfdIccBuffer,
                kIfdIccBufferOffset, kIfdIccBufferLength, DERIVATION_UWB_SESSION_ID, true);
    }

    public void deriveKeys(byte[] encKey, short encKeyOffset, byte[] macKey, short macKeyOffset,
            byte[] context, short contextOffset, short contextlength, byte[] output,
            short outputOffset) {
        if (mScp3Lib.scp03KDF(encKey, encKeyOffset, context, contextOffset,
                contextlength, DERIVATION_SENC, false, output, outputOffset)
                != SIGNATURE_BLOCK_SIZE ||
            mScp3Lib.scp03KDF(macKey, macKeyOffset, context, contextOffset,
                    contextlength, DERIVATION_SMAC, false, output,
                    (short) (outputOffset + SIGNATURE_BLOCK_SIZE)) != SIGNATURE_BLOCK_SIZE ||
            mScp3Lib.scp03KDF(macKey, macKeyOffset, context, contextOffset,
                    contextlength, DERIVATION_RMAC, false, output,
                    (short) (outputOffset + (SIGNATURE_BLOCK_SIZE * 2))) != SIGNATURE_BLOCK_SIZE) {
            // Crypto error
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void setSecurityLevel(byte level) {
        // Table 43 - Security Level
        if (level == CDECMAC_RENCMAC || level == CDECMAC_RMAC || level == CMAC_RMAC ||
                level == CDECMAC || level == CMAC) {
            mContext.mBuf[O_SECURITY_LEVEL] = level;
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }
}
