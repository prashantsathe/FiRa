package com.android.fira.applet;

public class Constant {
    public static final byte[] OID = {0x4f};
    public static final byte[] INSTANCE_UID = {0x4f};

    /* UWB_CONTROLEE_INFO start */
    public static final byte[] UWB_CAPABILITY_INFO = {(byte) 0x80};
    public static final byte[] UWB_CAPABILITIES = {(byte) 0xA3}; // Constructed Object
    public static final byte[] FIRA_PHY_VERSION_RANGE = {(byte) 0x80};
    public static final byte[] FIRA_MAC_VERSION_RANGE = {(byte) 0x81};
    public static final byte[] DEVICE_ROLES = {(byte) 0x82};
    public static final byte[] RANGING_METHOD = {(byte) 0x83};
    public static final byte[] STS_CONFIG = {(byte) 0x84};
    public static final byte[] MULTI_NODE_MODE = {(byte) 0x85};
    public static final byte[] RANGING_TIME_STRUCT = {(byte) 0x86};
    public static final byte[] SCHEDULED_MODE = {(byte) 0x87};
    public static final byte[] HOPPING_MODE = {(byte) 0x88};
    public static final byte[] BLOCK_STRIDING = {(byte) 0x89};
    public static final byte[] UWB_INITIATION = {(byte) 0x8A};
    public static final byte[] CHANNEL_NUMBER = {(byte) 0x8B};
    public static final byte[] RFRAME_CONFIG = {(byte) 0x8C};
    public static final byte[] CC_CONSTRAINT_LENGTH = {(byte) 0x8D};
    public static final byte[] BPRF_PARAMETER_SETS = {(byte) 0x8E};
    public static final byte[] HPRF_PARAMETER_SETS = {(byte) 0x8F};
    public static final byte[] AOA_SUPPORT = {(byte) 0x90};
    public static final byte[] SHORT_MAC_ADDRESS = {(byte) 0x91};
    public static final byte[] EXTENDED_MAC_ADDRESS = {(byte) 0x92};
    public static final byte[] STATIC_RANGING_INFO = {(byte) 0xA4}; // Constructed Object
    public static final byte[] VENDOR_ID = {(byte) 0x80};
    public static final byte[] STATIC_STS_IV = {(byte) 0x81};
    public static final byte[] SECURE_RANGING_INFO = {(byte) 0xA5}; // Constructed Object
    public static final byte[] UWB_SESSION_KEY_INFO = {(byte) 0x80};
    public static final byte[] UWB_SUB_SESSION_KEY_INFO = {(byte) 0x81};
    public static final byte[] SUS_ADDITIONAL_PARAMS = {(byte) 0x82};
    public static final byte[] REGULATORY_INFORMATION = {(byte) 0xA6}; // Constructed Object
    public static final byte[] INFORMATION_SOURCE = {(byte) 0x80};
    public static final byte[] OUTDOOR_PERMITTED = {(byte) 0x81};
    public static final byte[] COUNTRY_CODE = {(byte) 0x82};
    public static final byte[] TIMESTAMP = {(byte) 0x83};
    public static final byte[] CHANNEL5 = {(byte) 0x86};
    public static final byte[] CHANNEL6 = {(byte) 0x87};
    public static final byte[] CHANNEL8 = {(byte) 0x88};
    public static final byte[] CHANNEL9 = {(byte) 0x89};
    public static final byte[] CHANNEL10 = {(byte) 0x8A};
    public static final byte[] CHANNEL12 = {(byte) 0x8B};
    public static final byte[] CHANNEL13 = {(byte) 0x8C};
    public static final byte[] CHANNEL14 = {(byte) 0x8D};
    /* UWB_CONTROLEE_INFO end */

    /* UWB_SESSION_DATA start */
    public static final byte[] UWB_SESSION_DATA_VERSION = {(byte) 0x8D};
    public static final byte[] SESSION_ID = {(byte) 0x81};
    public static final byte[] SUB_SESSION_ID = {(byte) 0x82};
    public static final byte[] CONFIGURATION_PARAMETERS = {(byte) 0xA3}; // Constructed Object
    public static final byte[] FIRA_PHY_VERSION = {(byte) 0x80};
    public static final byte[] FIRA_MAC_VERSION = {(byte) 0x81};
    public static final byte[] DEVICE_ROLE = {(byte) 0x82};
    public static final byte[] PRF_MODE = {(byte) 0x8E};
    public static final byte[] SP0_PHY_SET = {(byte) 0x8F};
    public static final byte[] SP1_PHY_SET = {(byte) 0x90};
    public static final byte[] SP3_PHY_SET = {(byte) 0x91};
    public static final byte[] PREAMBLE_CODE_INDEX = {(byte) 0x92};
    public static final byte[] RESULT_REPORT_CONFIG = {(byte) 0x93};
    public static final byte[] MAC_ADDRESS_MODE = {(byte) 0x94};
    public static final byte[] DEVICE_MAC_ADDRESS = {(byte) 0x95};
    public static final byte[] DST_MAC_ADDRESS = {(byte) 0x96};
    public static final byte[] SLOTS_PER_RR = {(byte) 0x97};
    public static final byte[] RESPONDER_SLOT_INDEX = {(byte) 0x98};
    public static final byte[] MAX_CONTENTION_PHASE_LENGTH = {(byte) 0x99};
    public static final byte[] SLOT_DURATION = {(byte) 0x9A};
    public static final byte[] SLOTS_PER_RR_2 = {(byte) 0x9B};
    public static final byte[] RANGING_FREQUENCY = {(byte) 0x9C};
    public static final byte[] RESPONDER_SLOT_INDEX_2 = {(byte) 0x9C};
    public static final byte[] MAX_CONTENTION_PHASE_LENGTH_2 = {(byte) 0x9E};
    public static final byte[] KEY_ROTATION_RATE = {(byte) 0x9f, 0x1F};
    public static final byte[] MAC_FCS_TYPE = {(byte) 0x9f, 0x20};
    public static final byte[] MAX_RR_RETRY = {(byte) 0x9f, 0x21};
    public static final byte[] BLOCK_TIMING_STABILITY = {(byte) 0x9f, 0x22};
    public static final byte[] UWB_CONFIG_AVAILABLE = {(byte) 0x8D};
    /* UWB_SESSION_DATA end */

    public static final byte[] UWB_SESSION_DATA = {0x50};
    public static final byte[] FIRA_SC_CREDENTIAL = {0x51};
}
