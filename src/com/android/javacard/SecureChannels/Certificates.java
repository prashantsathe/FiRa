package com.android.javacard.SecureChannels;

import static com.android.javacard.SecureChannels.ScpConstant.*;

import com.android.javacard.ber.BerTlvParser;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Certificates {

    // TO avoid getter making members public
    public short[] mSignatureOffset;
    public short[] mSignatureDataOffset;
    public short[] mSignatureLength;
    public byte[] mBF20RegistryData;
    public short[] mBF20RegistryDataLength;
    public byte[] mCertificateKeyUsageStatus;   // 0x82 = Digital signature verification
                                                // 0x80 = Key Agreement
                                                // 0x88 = '88' encipherment for confidentiality
    public byte[] mPkOceEcka;
    public short[] mPkOceEckaSize;

    public Certificates() {

        mSignatureOffset = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mSignatureDataOffset = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mSignatureLength = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mBF20RegistryData = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_RESET); //TBD: size
        mBF20RegistryDataLength = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mCertificateKeyUsageStatus = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        mPkOceEcka = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
        mPkOceEckaSize = (short []) JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    }

    private boolean extractPublicKey(byte[] buffer, short bufferOffset, short bufferLen) {
        short index = 0, lenByteCnt = 0, dataLen = 0;
        byte status = 0x00;

        while (index < bufferLen) {
            // Table 6-14: Public Key Data Object
            // only single tag byte
            lenByteCnt = BerTlvParser.getTotalLengthBytesCount(buffer, (short) (bufferOffset + index + 1));
            dataLen = BerTlvParser.getDataLength(buffer, (short)(bufferOffset + index + 1));

            switch (buffer[(short)(bufferOffset + index)]) {
                case TAG_PUBLIC_KEY_Q:
                    mPkOceEckaSize[0] = dataLen;
                    Util.arrayCopyNonAtomic(buffer, (short) (bufferOffset + index + lenByteCnt + 1),
                                            mPkOceEcka, (short) 0, mPkOceEckaSize[0]);
                    status |= 0x01;
                    break;
                case TAG_KEY_PARAMETERS_REF:
                    status |= 0x02;
                    break;
                default:
                    return false;
            }
            index += (1 + lenByteCnt + dataLen);
        }

        // M = 2
        if (status != 0x03) {
            return false;
        }

        return true;
    }

    private boolean verifyCSN(byte[] csnBuff, short csnBuffOffset, short csnBuffLength) {
        return true;
    }

    /**
     * verify certificate defined in GPC_2.3_F_SCP11_v1.2.1 (Table 6-12: Certificate Format)
     *
     * @param buffer : buffer which contains certificate
     * @param bufferOffset : buffer offset
     * @param bufferLen : length of buffer/certificate
     * @param checkCSN : set if serial number verification required
     *
     * @return true if certificate verification is successful else false (exception)
     */
    public boolean verifyCert(byte[] buffer, short bufferOffset, short bufferLen, boolean checkCSN) {

        short certStatus = 0;
        short tagByteCnt = 0, lenByteCnt = 0, dataLen = 0;
        short index = 0, tag = 0;
        short bf20AuthOffset = 0, bf20AuthLength = 0;

        // Note:- No need to add BER parser (To avoid another loop)
        while (index < bufferLen) {
            tagByteCnt = BerTlvParser.getTotalTagBytesCount(buffer, (short) (bufferOffset + index));

            tag = tagByteCnt == 1 ?
                    (short) (buffer[(short) (bufferOffset + index)] & (short) 0xFF) :
                        Util.getShort(buffer, (short) (bufferOffset + index));

            index += tagByteCnt;
            lenByteCnt = BerTlvParser.getTotalLengthBytesCount(buffer, (short) (bufferOffset + index));
            dataLen = BerTlvParser.getDataLength(buffer, (short) (bufferOffset + index));
            index += (lenByteCnt + dataLen);

            // GPC_2.3_F_SCP11_v1.2.1
            // Table 6-12: Certificate Format
            switch (tag) {
                case TAG_CSN:
                    // Certificate Serial Number
                    certStatus |= 0x1;
                    // check csn is whitelisted
                    if (checkCSN && !verifyCSN(buffer, (short)
                                            (bufferOffset + index - dataLen) , dataLen)) {
                        ISOException.throwIt(CERT_NOT_IN_WHITELIST);
                    }
                    break;
                case TAG_KLOC_IDENTIFIER:
                    // CA-KLOC (or KA-KLOC) Identifier
                    certStatus |= 0x2;
                    break;
                case TAG_SUBJECT_IDENTIFIER:
                    // Subject Identifier
                    certStatus |= 0x4;
                    break;
                case TAG_KEY_USAGE:
                    //Key Usage:
                    certStatus |= 0x8;
                    if (dataLen == 1)
                        mCertificateKeyUsageStatus[0] = buffer[(short) (bufferOffset + index - dataLen)];
                    else
                        mCertificateKeyUsageStatus[0] = buffer[(short) (bufferOffset + index - dataLen + 1)];
                    break;
                case TAG_EFFECTIVE_DATE:
                    // Effective Date (YYYYMMDD, BCD format)
                    certStatus |= 0x10;
                    break;
                case TAG_EXPIRATION_DATE:
                    // Expiration Date
                    certStatus |= 0x20;
                    break;
                case TAG_DISCRETIONARY_DATE:
                case TAG_DISCRETIONARY_DATE2:
                    // Discretionary Data
                    certStatus |= 0x40;
                    break;
                case TAG_SCP11C_AUTHORIZATION:
                    // Authorizations under SCP11c
                    certStatus |= 0x80;
                    bf20AuthOffset = (short) (index - dataLen);
                    bf20AuthLength = dataLen;
                    break;
                case TAG_PUBLIC_KEY:
                    // Public Key – for details, see tables below
                    certStatus |= 0x100;

                    if (!extractPublicKey(buffer, (short) (bufferOffset + index - dataLen), dataLen)) {
                        return false;
                    }

                    break;
                case TAG_SIGNATURE:
                    // Signature
                    // Signature should be last tag information from the certificate format
                    certStatus |= 0x200;
                    mSignatureOffset[0] = (short) (index - lenByteCnt - dataLen - tagByteCnt);
                    mSignatureDataOffset[0] = (short) (index - dataLen);
                    mSignatureLength[0] = dataLen;
                    break;
                default:
                    // return false if tags other than certificate format tags found
                    return false;
            }
        }

        // Check if all mandatory fields are present
        // M = 7
        if ((short) (certStatus & (short) 0x32f) != (short) 0x32f) {
            return false;
        }

        // tag 'BF20' shall be absent in a signature verification
        // certificate (i.e. value '82' for tag '95').
        if ((mCertificateKeyUsageStatus[0] == 0x82) &&
                (short) (certStatus & (short) 0x80) == (short) 0x80) {
            ISOException.throwIt(BF20_NOT_SUPPORTED);
        }

        // save 'BF20' if present, should be check only for last certificate
        // TODO : B.2 Limitations on Commands Received through SCP11c
        if ((mCertificateKeyUsageStatus[0] == 0x80) &&
                (short) (certStatus & (short) 0x80) == (short) 0x80) {
            // As per requirement we have to verify the unwrap command
            Util.arrayCopyNonAtomic(buffer, (short) (bufferOffset + bf20AuthOffset),
                    mBF20RegistryData, (short) 0, bf20AuthLength);
            mBF20RegistryDataLength[0] = bf20AuthLength;
        }

        return true;
    }
}
