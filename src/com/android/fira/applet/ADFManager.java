package com.android.fira.applet;

import com.android.ber.BerArrayLinkList;
import com.android.ber.BerTlvParser;

public class ADFManager {
    private BerTlvParser berTlvParser;

    public ADFManager() {
        berTlvParser = new BerTlvParser();
    }

    /* Validate the ADF structure */
    public boolean parser(byte[] buffer, short offSet, short length) {
        BerArrayLinkList berList = berTlvParser.parser(buffer, offSet, length);
        berList.printAllTags(buffer);

        /* Error message and error response */
        return validateADF(buffer, berList);
    }

    private boolean validateADF(byte[] buffer, BerArrayLinkList berList) {
        short ptrOffset = berList.getTLVInstance(Constant.indexesADF.OID.getValue(), (short) -1);

        // OID
        if (!validateOID(buffer,ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) return false;
        if (Constant.INSTANCE_UID[0] == buffer[berList.getTagOffset(ptrOffset)]) {
            if ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) return false;
        }

        // UWB controlee info
        if (!validateUWBControleeInfo(buffer, ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) return false;
        // Check UWB Session data
        if (!validateUWBSessionData(buffer, ptrOffset, berList)) {
            return false;
        }

        if ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) return false;
        if (Constant.ACCESS_CONDITIONS[0] == buffer[berList.getTagOffset(ptrOffset)]) {
            if ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) return false;
        }

        if (Constant.ADF_PROVISIONING_CREDENTIAL[0] == buffer[berList.getTagOffset(ptrOffset)]) {
            if ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) return false;
        }

        // Fira SC credential
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
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.UWB_CAPABILITIES[0] == buffer[berList.getTagOffset(ptrOffset)]) &&      /* UWB capabilities */
                (Constant.UWB_CAPABILITIES_LENGTH == berList.getLength(ptrOffset)) &&/* TODO: Need to check inner Tags? */
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.STATIC_RANGING_INFO[0] == buffer[berList.getTagOffset(ptrOffset)]) &&/* Static ranging info */
                (Constant.STATIC_RANGING_INFO_LENGTH == berList.getLength(ptrOffset)) &&
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.SECURE_RANGING_INFO[0] == buffer[berList.getTagOffset(ptrOffset)]) &&/* Secure ranging info */
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.REGULATORY_INFORMATION[0] == buffer[berList.getTagOffset(ptrOffset)]) && /* Regulatory info */
                (Constant.REGULATORY_INFORMATION_LENGTH == berList.getLength(ptrOffset));
    }

    private boolean validateUWBSessionData(byte[] buffer, short ptrOffset, BerArrayLinkList berList) {

        return (Constant.UWB_SESSION_DATA_VERSION[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.SESSION_ID[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.SUB_SESSION_ID[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.CONFIGURATION_PARAMETERS[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
                (validateConfigurationParameters()) &&
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.STATIC_RANGING_INFO[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
                (Constant.STATIC_RANGING_INFO_LENGTH == berList.getLength(ptrOffset)) &&/* TODO: Need to check inner Tags? */
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.SECURE_RANGING_INFO[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
                (ValidateSecureRangingInfo()) &&
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.REGULATORY_INFORMATION[0] == buffer[berList.getTagOffset(ptrOffset)]) &&
                (Constant.REGULATORY_INFORMATION_LENGTH == berList.getLength(ptrOffset)) &&/* TODO: Need to check inner Tags? */
                ((ptrOffset = berList.getNextTag(ptrOffset)) != -1) &&
                (Constant.UWB_CONFIG_AVAILABLE[0] == buffer[berList.getTagOffset(ptrOffset)]);
    }

    private boolean validateConfigurationParameters() {
        return true;
    }

    private boolean ValidateSecureRangingInfo() {
        return true;
    }

    private boolean validateFIRaSCCredential(byte[] buffer, short offsetSCCredential, BerArrayLinkList berList) {
        short ptr = berList.getTLVInstance(offsetSCCredential, (short) -1);
        byte tagCredential = buffer[berList.getTagOffset(ptr)];

        return (tagCredential >=Constant.FIRA_SC_CREDENTIAL_ADF_BASE_KEY[0] &&
                tagCredential <= Constant.FIRA_SC_CREDENTIAL_UWB_RANGING_ROOT_KEY[0]);
    }


}
