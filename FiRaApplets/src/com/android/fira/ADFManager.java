package com.android.fira;

import com.android.ber.BerArrayLinkList;
import com.android.ber.BerTlvParser;
import javacard.framework.Util;

public class ADFManager {
    private BerTlvParser mBerTlvParser;
    private static CryptoManager mCryptoManager;

    public ADFManager() {
        mBerTlvParser = new BerTlvParser();
        mCryptoManager = new CryptoManager();
    }

    /* Encrypt the ADF(secure Blob) received from Import ADF */
    public short encryptImportAdf(byte[] adfTlv, short offSet, byte[] out, short outOffset) {
        return mCryptoManager.aesCBC128NoPadEncrypt(adfTlv, offSet, (short) 480, out,outOffset);
    }

    /* Validate the ADF structure / Swap adf secure-blob */
    public boolean parserAndValidateSwapAdf(byte[] buffer, short offSetBuffer, short lengthBuffer,
                                            byte[] heapBuffer, short offSetHeapBuffer, short lengthHeapBuffer) {

        short swapOidOffset = 0;
        short swapUWBOffset = 0;

        /* check OID */
        if (heapBuffer[offSetHeapBuffer] != 0x06) return false;

        // length calculation , oid tag bytes count is 1
        swapOidOffset += 1;
        swapOidOffset += mBerTlvParser.getTotalLengthBytesCount(heapBuffer, (short) (offSetHeapBuffer + 1));
        swapOidOffset += mBerTlvParser.getDataLength(heapBuffer, (short) (offSetHeapBuffer + 1));

        /* Check UWB info */
        if (heapBuffer[swapOidOffset] != (byte) 0xBF || heapBuffer[(short)(swapOidOffset + 1)] != 0x70) return false;

        // length calculation, UWB tag bytes count is 2
        swapUWBOffset += 2;
        swapUWBOffset += mBerTlvParser.getTotalLengthBytesCount(heapBuffer, (short) (offSetHeapBuffer + swapOidOffset + 2));
        swapUWBOffset += mBerTlvParser.getDataLength(heapBuffer, (short) (offSetHeapBuffer + swapOidOffset + 2));

        short swapSecureBlob = (short) (swapOidOffset + swapUWBOffset);
        if (heapBuffer[swapSecureBlob] != (byte) 0xDF || heapBuffer[(short)(swapSecureBlob + 1)] != 0x51) return false;

        // length calculation, secure Blob tag bytes count is 2,
        short secureBlobByteLengthCount =  mBerTlvParser.getTotalLengthBytesCount(heapBuffer, (short) (swapSecureBlob + 2));
        short secureBlobLength = mBerTlvParser.getDataLength(heapBuffer, (short) (swapSecureBlob + 2));

        // Copy OID&UWB info to 'buffer'
        Util.arrayCopyNonAtomic(heapBuffer, offSetHeapBuffer, buffer, offSetBuffer, swapSecureBlob);
        if (Constant.ADF_PACS_PROFILE_SIZE != mCryptoManager.aesCBC128NoPadDecrypt(heapBuffer,
                                (short) (offSetHeapBuffer + swapSecureBlob + 2 + secureBlobByteLengthCount),
                                secureBlobLength, buffer, (short) (offSetBuffer + swapSecureBlob))) {
            /*TODO:- */
            return false;
        }

        BerArrayLinkList berList = mBerTlvParser.parser(buffer, offSetBuffer,
                                (short) (swapSecureBlob + 2 + secureBlobByteLengthCount + Constant.ADF_PACS_PROFILE_SIZE));

        /* Error message and error response */
        return validatePACsADF(buffer, berList);
    }

    private boolean validatePACsADF(byte[] buffer, short bufferOffset, BerArrayLinkList berList) {
        short ptrOffset = berList.getTLVInstance(Constant.PACS_UWB_CAPABILITIES, (short) -1);

        // UWB capabilities
        if (!validateUWBCapabilities(buffer, ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        // Check UWB Session data
        if (!validateUWBSessionData(buffer, ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        if (Constant.FIRA_SC_CREDENTIAL[0] == buffer[berList.getTagOffset(ptrOffset)]) {
            return false;
        }

        return true;
    }

    private boolean validatePACsADF(byte[] buffer, BerArrayLinkList berList) {
        short ptrOffset = berList.getTLVInstance(Constant.PACS_UWB_CAPABILITIES, (short) -1);

        // UWB capabilities
        if (!validateUWBCapabilities(buffer, ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        // Check UWB Session data
        if (!validateUWBSessionData(buffer, ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        if (Constant.FIRA_SC_CREDENTIAL[0] != buffer[berList.getTagOffset(ptrOffset)]) {
            return false;
        }

        return true;
    }

    private boolean validateUWBCapabilities(byte[] buffer, short ptrOffset, BerArrayLinkList berList) {
        return  (Constant.UWB_CAPABILITIES[0] == buffer[berList.getTagOffset(ptrOffset)]); /* UWB capabilities */
                /* TODO: Check all parameters */
    }

    /* CSML ADF content verification */
    private boolean validateADF(byte[] buffer, BerArrayLinkList berList) {
        short ptrOffset = berList.getTLVInstance(Constant.PACS_OID, (short) -1);

        // OID
        if (!validateOID(buffer,ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        if (Constant.INSTANCE_UID[0] == buffer[berList.getTagOffset(ptrOffset)]) {
            if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        }

        // UWB controlee info
        if (!validateUWBControleeInfo(buffer, ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        // Check UWB Session data
        if (!validateUWBSessionData(buffer, ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        if (Constant.ACCESS_CONDITIONS[0] == buffer[berList.getTagOffset(ptrOffset)]) {
            if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        }

        if (Constant.ADF_PROVISIONING_CREDENTIAL[0] == buffer[berList.getTagOffset(ptrOffset)]) {
            if ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) return false;
        }

        // FiRa SC credential
        if (!validateFIRaSCCredential(buffer, ptrOffset, berList)) {
            return false;
        }

        return true;
    }

    private boolean validateOID(byte[] buffer, short ptrOffset, BerArrayLinkList berList) {
        return (Constant.OID[0] == buffer[berList.getTagOffset(ptrOffset)]) && (berList.getLength(ptrOffset) >= 1);
    }

    private boolean validateUWBControleeInfo(byte[] buffer, short ptrOffset, BerArrayLinkList berList) {

        return (Constant.UWB_CAPABILITY_VERSION[0] == buffer[berList.getTagOffset(ptrOffset)]) &&          /* Version */
                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
                (Constant.UWB_CAPABILITIES[0] == buffer[berList.getTagOffset(ptrOffset)]) &&      /* UWB capabilities */
                (Constant.UWB_CAPABILITIES_LENGTH == berList.getLength(ptrOffset)) &&/* TODO: Need to check inner Tags? */
                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
                (Constant.STATIC_RANGING_INFO[0] == buffer[berList.getTagOffset(ptrOffset)]) &&/* Static ranging info */
                (Constant.STATIC_RANGING_INFO_LENGTH == berList.getLength(ptrOffset)) &&
                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
                (Constant.SECURE_RANGING_INFO[0] == buffer[berList.getTagOffset(ptrOffset)]) &&/* Secure ranging info */
                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
                (Constant.REGULATORY_INFORMATION[0] == buffer[berList.getTagOffset(ptrOffset)]) && /* Regulatory info */
                (Constant.REGULATORY_INFORMATION_LENGTH == berList.getLength(ptrOffset));
    }

    private boolean validateUWBSessionData(byte[] buffer, short ptrOffset, BerArrayLinkList berList) {

        return (Constant.UWB_SESSION_DATA_VERSION[0] == buffer[berList.getTagOffset(ptrOffset)]); //&&
//                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
//                (Constant.SESSION_ID[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
//                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
//                (Constant.SUB_SESSION_ID[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
//                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
//                (Constant.CONFIGURATION_PARAMETERS[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
//                (validateConfigurationParameters()) &&
//                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
//                (Constant.STATIC_RANGING_INFO[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
//                (Constant.STATIC_RANGING_INFO_LENGTH == berList.getLength(ptrOffset)) &&/* TODO: Need to check inner Tags? */
//                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
//                (Constant.SECURE_RANGING_INFO[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
//                (ValidateSecureRangingInfo()) &&
//                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
//                (Constant.REGULATORY_INFORMATION[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
//                (Constant.REGULATORY_INFORMATION_LENGTH == berList.getLength(ptrOffset)) &&/* TODO: Need to check inner Tags? */
//                ((ptrOffset = berList.getNextTag(ptrOffset)) == -1) &&
//                (Constant.UWB_CONFIG_AVAILABLE[0] == buffer[berList.getTagOffset(ptrOffset)]);
    }

    private boolean validateFIRaSCCredential(byte[] buffer, short offsetSCCredential, BerArrayLinkList berList) {
        short ptr = berList.getTLVInstance(offsetSCCredential, (short) -1);
        byte tagCredential = buffer[berList.getTagOffset(ptr)];

        return (tagCredential >=Constant.FIRA_SC_CREDENTIAL_ADF_BASE_KEY[0] &&
                tagCredential <= Constant.FIRA_SC_CREDENTIAL_UWB_RANGING_ROOT_KEY[0]);
    }
}
