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

import com.android.javacard.ber.BerTlvBuilder;
import com.android.javacard.ber.BerTlvParser;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Scp11Lib {

    // Note:  AUTHENTICATED is achieved if the owner of the SD or Application authenticates.
    // The SD identifies the owner by the Subject Identifier (TLV with tag '5F20') in the OCE
    // certificate matching the Application Provider Identifier of the SD
    // or Application, which was provided as a parameter (TLV with tag '5F20' within the CRT TLV
    // with tag 'B6') in the INSTALL [for install] command.
    // For FiRa:- SCP11c will be used as a custom library, part of application; so The authentication
    //            level for FiRa will always be 'ANY_AUTHENTICATED'
    private byte[] msecurityLevel;

    private byte[] mEPkOceEcka;
    private short[] mEPkOceEckaSize;

    private byte[] mKeySetBuff;
    private Crypto mCrypto;
    private Scp3Lib mScp3Lib;
    private FiraClientContext mFiraClientContext;
    private static byte[] sInData;
    private static byte[] sOutData;
    private static Certificates sCertificate;

    private void Scp11LibInit(FiraClientContext firaClientContext) {
        msecurityLevel = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mEPkOceEcka = JCSystem.makeTransientByteArray(EPHEMERAL_PK_SIZE, JCSystem.CLEAR_ON_RESET);
        mEPkOceEckaSize = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mKeySetBuff = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_RESET);
        InitStaticFields();
        mFiraClientContext = firaClientContext;
    }

    private void InitStaticFields() {
        // Check just one field for NULL
        if (sInData == null) {
            sInData = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_RESET);
            sOutData = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
            sCertificate = new Certificates();
        }
    }

    public Scp11Lib(FiraClientContext firaClientContext) {
        if (mCrypto == null)
            mCrypto = new Crypto();

        if (mScp3Lib == null)
            mScp3Lib = new Scp3Lib();

        Scp11LibInit(firaClientContext);
    }

    public Scp11Lib(Crypto crypto, Scp3Lib scp3Lib, FiraClientContext firaClientContext) {
        mCrypto = crypto;
        mScp3Lib = scp3Lib;
        Scp11LibInit(firaClientContext);
    }

    private void setSecurityLevel(byte keyUsageQual) {

        if (keyUsageQual == AUTH_CMAC_RMAC) {
            msecurityLevel[0] = (ANY_AUTHENTICATED | C_MAC | R_MAC);
        } else if (keyUsageQual == AUTH_CMACDES_RMACENC) {
            msecurityLevel[0] = (ANY_AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION);
        } else if (keyUsageQual == AUTH_CMACDES) {
            msecurityLevel[0] = (ANY_AUTHENTICATED | C_MAC | C_DECRYPTION);
        } else if (keyUsageQual == AUTH_CMACDES_RMAC) {
            msecurityLevel[0] = (ANY_AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC);
        } else {
            ISOException.throwIt(INCORRECT_VAL_IN_CMD);
        }
    }

    //  The concatenation of the following values shall be used for SharedInfo as input for the Key Derivation process:
    //  • Key usage qualifier (1 byte)
    //  • Key type (1 byte)
    //  • Key length (1 byte)
    //  • If Host and Card ID are requested:
    //  o In the case of SCP11a and SCP11b: HostID-LV, SIN-LV, and SDIN-LV
    //  o In the case of SCP11c: HostID-LV and Card Group ID-LV
    //
    private short deriveSessionKey(byte keyUsageQual, byte keyType, byte keyLength,
            byte[] hostCardID, short hostCardIDOffset, short hostCardIDLength, byte kId, byte kVn) {

        short ShSssSize = 0, ShSesSize = 0;
        short ShSLength = 0;
        short skSdEckaSize = ClientContext.getSkSdEcka(kVn, mKeySetBuff, (short) 0, mFiraClientContext);

        if (skSdEckaSize == (short) 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // generate 'ShS' / add 'ShS' to sInData at '0'
        ShSesSize = mCrypto.generateSecretEC_SVDP_DHC(mKeySetBuff, (short)0, skSdEckaSize,
                mEPkOceEcka, (short)0, mEPkOceEckaSize[0], sInData, (short)0);

        ShSssSize = mCrypto.generateSecretEC_SVDP_DHC(mKeySetBuff, (short)0, skSdEckaSize,
                sCertificate.mPkOceEcka, (short)0, sCertificate.mPkOceEckaSize[0], sInData, ShSesSize);

        // add shared info to sInData at 'ShSesSize + ShSssSize'
        ShSLength = (short) (ShSesSize + ShSssSize);
        sInData[ShSLength] = keyUsageQual;
        sInData[(short)(ShSLength + 1)] = keyType;
        sInData[(short)(ShSLength + 2)] = keyLength;
        if (hostCardIDLength > (short)0) {
            Util.arrayCopyNonAtomic(hostCardID, hostCardIDOffset, sInData, (short) (ShSLength + 3), hostCardIDLength);
        }

        // As per Table 6-18: KeyData Assignment, number of keys are 5
        return mCrypto.kdfX963(sInData, (short)0, ShSLength, sInData, ShSLength,
                                (short)(3 + hostCardIDLength), (short) (keyLength * 5),
                                   sOutData, (short) 0);
    }

    private short generateReceiptAndResponse(byte[] buffer, short bufferOffset, short tagA6Offset, short tagA6Length,
            short tag5f49Offset, short tag5f49Length, byte keyUsageQual, byte keyType, byte keyLength,
            byte[] hostCardID, short hostCardIDOffset, short hostCardIDLength, byte kId, byte kVn,
            byte[] sendOutBuff, short sendOutBuffOffset) {

        short inputDataOffset = 0, inputDataLength = 0;
        short byteCnt = 0;

        // get pkSdEcka/skSdEcka
        short pkSdEckaSize = ClientContext.getPkSdEcka(kVn, mKeySetBuff, (short) 0,
                mFiraClientContext);

        if (pkSdEckaSize == (short) 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // return keys size is (5*keyLength) and keys are stored in 'sOutData'
        short keysLength = deriveSessionKey(keyUsageQual, keyType, keyLength, hostCardID,
                                hostCardIDOffset, hostCardIDLength, kId, kVn);

        if (keysLength == -1) {
            return keysLength;
        }

        // Extract keys defined in Table 6-18: KeyData Assignment for further use.
        mScp3Lib.setKeys(sOutData, keyLength, keyLength);

        // Table 6-19: Input Data for Receipt Calculation
        // store input data in to sInData from "keyStartOffset + (keyLength*5)"
        // Copy A6 tag
        Util.arrayCopyNonAtomic(buffer, (short)(bufferOffset + tagA6Offset), sInData,
                inputDataOffset, tagA6Length);
        inputDataLength += tagA6Length;

        // copy '5F49' tag ePK.OCE.ECKA
        Util.arrayCopyNonAtomic(buffer, (short)(bufferOffset + inputDataLength), sInData,
            (short)(inputDataOffset + tagA6Length), tag5f49Length);
        inputDataLength += tag5f49Length;

        // copy '5F49' tag PK.SD.ECKA
        sInData[inputDataLength++] = 0x5f;
        sInData[inputDataLength++] = 0x49;
        inputDataLength += BerTlvBuilder.fillLength(sInData, pkSdEckaSize, inputDataLength);
        Util.arrayCopyNonAtomic(mKeySetBuff, (short) 0, sInData,
                (short) (inputDataOffset + inputDataLength), pkSdEckaSize);
        inputDataLength += pkSdEckaSize;

        // Table 6-20: MUTUAL AUTHENTICATE Response Data
        // Add SCP11c: PK.SD.ECKA in data response then generate receipt to add the receipt
        // at the end
        short index = 0;

        sendOutBuff[(short) (sendOutBuffOffset + (index++))] = 0x5F;
        sendOutBuff[(short) (sendOutBuffOffset + (index++))] = 0x49;
        byteCnt = BerTlvBuilder.fillLength(sendOutBuff, pkSdEckaSize, (short) (sendOutBuffOffset + index));
        index += byteCnt;

        Util.arrayCopyNonAtomic(mKeySetBuff, (short)0, sendOutBuff,
                (short)(sendOutBuffOffset + index), pkSdEckaSize);
        index += pkSdEckaSize;

        sendOutBuff[(short)(sendOutBuffOffset + (index++))] = (byte) 0x86;
        sendOutBuff[(short)(sendOutBuffOffset + (index++))] = 0x10;

        // generate and store the receipt in sendOutBuff
        mCrypto.genCmacAes128(sOutData, (short) 0, (short) keyLength,
                sInData, inputDataOffset, inputDataLength, sendOutBuff, (short) (sendOutBuffOffset + index));

        return (short) (index + 16); // 'genCmacAes128' generates 16 bytes of cmac
    }

    /**
     * verify CRT content and generate the receipt using private/public keys based on 'kvn'
     *
     * @param buffer : incoming buffer
     * @param bufferOffset : start index of buffer
     * @param bufferLen : length of buffer
     * @param kId :
     * @param kVn : key version of private/public ECKA keys of SD
     * @param sendOutBuff : buffer where receipt is generated
     * @param sendOutBuffOffset : offset of s'sendOutBuff'
     *
     * @return length of generated receipt if successful (else exception)
     */
    public short parseAndVerifyCrtGenerateReceipt(byte[] buffer, short bufferOffset, short bufferLen,
            byte kId, byte kVn, byte[] sendOutBuff, short sendOutBuffOffset) {

        short index = 0, dataLenByteCnt = 0, dataLen = 0, tagByteCnt = 0;
        short tag = 0;
        byte muDataFieldCRTStatus = 0;
        short crtIndex;
        short tagA6Offset = 0, tagA6Length = 0, tag5f49Offset = 0,tag5f49Length = 0;
        byte keyUsageQual = 0, keyType = 0, keyLength = 0;
        boolean includeHostCardID = false;

        // Check for pkSdEcka/skSdEcka
        if (ClientContext.getSkSdEcka(kVn, mKeySetBuff, (short) 0, mFiraClientContext) == (short) 0) {
            ISOException.throwIt(PK_KLOC_NOT_FOUND);
        }

        // First : verify CRA content
        // GPC_2.3_F_SCP11_v1.2.1
        // Table 6-17: Control Reference Template (Key Agreement)
        // Note:- No need to add BER parser (To avoid another loop)
        while (index < bufferLen) {

            tagByteCnt = BerTlvParser.getTotalTagBytesCount(buffer, (short) (bufferOffset + index));

            tag = tagByteCnt == 1 ?
                    (short) (buffer[(short) (bufferOffset + index)] & (short) 0xFF) :
                        Util.getShort(buffer, (short) (bufferOffset + index));

            index += tagByteCnt;
            dataLenByteCnt = BerTlvParser.getTotalLengthBytesCount(buffer, (short) (bufferOffset + index));
            dataLen = BerTlvParser.getDataLength(buffer, (short)(bufferOffset + index));
            index += dataLenByteCnt;

            if (tag == TAG_CRT) {
                muDataFieldCRTStatus |= 0x01;
                tagA6Offset = (short) (index - tagByteCnt - dataLenByteCnt);
                tagA6Length = (short) (index + dataLen);

                crtIndex = 0;
                // Verify CRT
                while (crtIndex < dataLen) {
                    // CRT does not have 2 bytes tag
                    switch (buffer[(short)(crtIndex + index + bufferOffset)]) {
                        case TAG_SCP_IDENTIFIFER:
                            // SCP identifier and parameters
                            muDataFieldCRTStatus |= 0x02;
                            // table: 6.2 SCP Identifier and Parameters
                            // we checking here Only scp11c (0x03 = '11C')
                            if (buffer[(short)(crtIndex + index + bufferOffset + 2)] != 0x11 || 
                                ((buffer[(short)(crtIndex + index + bufferOffset + 3)] & 0x03)
                                        != 0x03)) {
                                ISOException.throwIt(INCORRECT_VAL_IN_CMD);
                            }

                            includeHostCardID = (buffer[(short)(crtIndex + index + bufferOffset + 3)]
                                    & 0x04) == 0x04 ? true : false;
                            crtIndex += 4;
                            break;
                        case TAG_KEY_USAGE_QUALIFIER:
                            // Key Usage Qualifier
                            muDataFieldCRTStatus |= 0x04;
                            keyUsageQual = buffer[(short)(crtIndex + index + bufferOffset + 2)];
                            crtIndex += 3;
                            break;
                        case TAG_KEY_TYPE:
                            // Key Type
                            muDataFieldCRTStatus |= 0x08;
                            keyType = buffer[(short)(crtIndex + index + bufferOffset + 2)];
                            crtIndex += 3;
                            break;
                        case TAG_KEY_LENGTH:
                            // Key Length (in bytes)
                            muDataFieldCRTStatus |= 0x10;
                            keyLength = buffer[(short)(crtIndex + index + bufferOffset + 2)];
                            crtIndex += 3;
                            break;
                        case TAG_HOSTID:
                            // HostID (shall only be present if SCP parameter b3 is
                            // set)
                            if (includeHostCardID == false) {
                                ISOException.throwIt(INCORRECT_VAL_IN_CMD);
                            }
                            muDataFieldCRTStatus |= 0x20;
                            // TODO: Host ID copying 
                            break;
                        default:
                            // in case other tags other than CRT
                            ISOException.throwIt(INCORRECT_VAL_IN_CMD);
                    }
                }

            } else if (tag == TAG_PK_OCE_ECKA) {
                muDataFieldCRTStatus |= 0x40;
                tag5f49Offset = (short) (index - tagByteCnt - dataLenByteCnt);
                tag5f49Length = (short) (dataLen + 2 + dataLenByteCnt);
                // Copy Key
                Util.arrayCopyNonAtomic(buffer, (short) (bufferOffset + index),
                                    mEPkOceEcka,(short)0, dataLen);
                mEPkOceEckaSize[0] = dataLen;
            } else {
                // in-case any other tag
                ISOException.throwIt(INCORRECT_VAL_IN_CMD);
            }

            index += dataLen;
        }

        // Check if all mandatory fields are present
        // M = 6
        if ((short) (muDataFieldCRTStatus & 0x5F) != (short) 0x5f) {
            // '6A' '80' Incorrect values in command data
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        setSecurityLevel(keyUsageQual);

        return generateReceiptAndResponse(buffer, bufferOffset, tagA6Offset, tagA6Length,
                tag5f49Offset, tag5f49Length, keyUsageQual, keyType, keyLength, null,
                (short) 0, (short) 0, kId, kVn, sendOutBuff, sendOutBuffOffset);
    }

    /**
     * verify the certificate and corresponding signature using 'pkcakloc' key based 
     * on 'keyVersion' defined in the 'buffer'
     *
     * @param buffer : incoming buffer
     * @param offset : start index of buffer
     * @param length : length of buffer
     * @param keyIdentifier
     * @param keyVersion : key version of 'pkcakloc'
     * 
     * @return false if verification failed else success
     */
    public boolean parseAndVerifySignature(byte[] buffer, short offset, short length,
                                           byte keyIdentifier, byte keyVersion) {

        short index = 0, dataLen = 0, dataLenByteCnt = 0;
        boolean firstCert = true;

        // First: get mPkCaKlocEcdsa certificate using kversion 
        short pkCaKlocEcdsaSize = ClientContext.getPkCaKlocEcdsa(keyVersion, mKeySetBuff,
                (short) 0, mFiraClientContext);

        if (pkCaKlocEcdsaSize == (short) 0) {
            ISOException.throwIt(PK_KLOC_NOT_FOUND);
        }

        // GPC_2.3_F_SCP11_v1.2.1
        // Table 6-12: Certificate Format
        while (index < length) {
            // Check first TAG '7F21'
            if (Util.getShort(buffer, (short) (offset + index)) != TAG_CERTIFICATE)
                return false;

            index += 2;
            dataLenByteCnt = BerTlvParser.getTotalLengthBytesCount(buffer, (short) (offset + index));
            dataLen = BerTlvParser.getDataLength(buffer, (short) (offset + index));
            index += dataLenByteCnt;

            // verify Certificate and Signature
            /* Notes:-
             * 1) in-case of certificate chaining immediate PK will be stored in 'mPkOceEcka' itself which 
             *    will be used as a verifier key for next certificate. (at the end 'mPkOceEcka' is a final 
             *    key, if '00 80': Key agreement is present)
             * 2) GPC_2.3_F_SCP11_v1.2.1 section 6.4.1
             *    - If no whitelist is defined for the referenced PK.CA-KLOC.ECDSA (see section 6.8), CSNs found in the
             *    certificate chain shall not be checked. Otherwise, if the CSN of the first (or only)
             *    CERT.KA-KLOC.ECDSA is not referenced in the whitelist, then the certificate (and the entire
             *    certificate chain) shall be rejected. Other CSNs found in the certificate chain shall not be checked (i.e.
             *    other certificates following in the chain are not required to be referenced in this whitelist in order to be
             *    accepted).
             *    - If certificate chaining is not used, only CERT.OCE.ECKA is submitted and:
             *    If no whitelist is defined for the referenced PK.CA-KLOC.ECDSA (see section 6.8),
             *    the CSN of CERT.OCE.ECKA shall not be checked. Otherwise, if this CSN is not
             *    referenced in the whitelist, then the certificate shall be rejected.
             */
            if (!sCertificate.verifyCert(buffer, (short) (offset + index), dataLen, firstCert/*for CSN check*/) ||
                    !mCrypto.verifyECDSAPlainSignatureSha256(
                            firstCert ? mKeySetBuff : sCertificate.mPkOceEcka, (short) 0,
                                    firstCert ? pkCaKlocEcdsaSize: sCertificate.mPkOceEckaSize[0], buffer,
                            (short) (offset + index), sCertificate.mSignatureOffset[0], buffer,
                            (short) (offset + sCertificate.mSignatureDataOffset[0] + index),
                            sCertificate.mSignatureLength[0])) {
                ISOException.throwIt(CERT_VERIFICATION_FAILED);
            }

            // if CERT.OCE.ECKA ('00 80': Key agreement) found return success
            if (sCertificate.mCertificateKeyUsageStatus[0] == (byte) 0x80) {
                return true;
            }

            index += dataLen;
            firstCert = false;
        }

        return false;
    }

    /**
     * Wrap(encrypt) incoming 'buff' start from 'buffOffset' based on assigned
     * 'mSecurityLevel' having length 'buffLen'
     *
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     * @param resApdu : true when response apdu else false for command apdu
     *
     * @return length of wrapped data in 'buff' starting from 'buffOffset'
     */
    public short wrap(byte[] buff, short buffOffset, short buffLen, boolean resApdu) {
        return mScp3Lib.wrap(msecurityLevel[0], buff, buffOffset, buffLen, resApdu);
    }

    /**
     * Unwrap(decrypt) incoming 'buff' start from 'buffOffset' based on assigned
     * 'mSecurityLevel' having length 'buffLen'
     *
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     * @param resApdu : true when response apdu else false for command apdu
     *
     * @return length of unwrapped data in 'buff' starting from 'buffOffset'
     */
    public short unwrap(byte[] buff, short buffOffset, short buffLen, boolean resApdu) {
        return mScp3Lib.unwrap(msecurityLevel[0], buff, buffOffset, buffLen, resApdu);
    }

    /**
     * get current security level
     *
     * @return current security level
     */
    public byte getSecurityLevel() {
        return msecurityLevel[0];
    }

    /**
     * Reset scp11 and corresponding scp03 context (secret keys)
     */
    public void reset() {
        Util.arrayFillNonAtomic(mEPkOceEcka, (short) 0, EPHEMERAL_PK_SIZE, (byte) 0x00);
        mScp3Lib.reset();
    }
}
