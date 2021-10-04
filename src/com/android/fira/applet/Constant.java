package com.android.fira.applet;

public class Constant {
    /* UWB_CONTROLEE_INFO start */
    public static final byte[] UWB_CAPABILITY_VERSION = {(byte) 0x80};
    public static final byte[] UWB_CAPABILITIES = {(byte) 0xA3}; // Constructed Object
    public static final short UWB_CAPABILITIES_LENGTH = 78;
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
    public static final short STATIC_RANGING_INFO_LENGTH = 8;
    public static final byte[] VENDOR_ID = {(byte) 0x80};
    public static final byte[] STATIC_STS_IV = {(byte) 0x81};
    public static final byte[] SECURE_RANGING_INFO = {(byte) 0xA5}; // Constructed Object
    public static final byte[] UWB_SESSION_KEY_INFO = {(byte) 0x80};
    public static final byte[] UWB_SUB_SESSION_KEY_INFO = {(byte) 0x81};
    public static final byte[] SUS_ADDITIONAL_PARAMS = {(byte) 0x82};
    public static final byte[] REGULATORY_INFORMATION = {(byte) 0xA6}; // Constructed Object
    public static final short REGULATORY_INFORMATION_LENGTH = 40;
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
    public static final byte[] UWB_SESSION_DATA_VERSION = {(byte) 0x80};
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

    /* ADF content */
    public static final byte[] OID = {0x41};
    public static final byte[] INSTANCE_UID = {0x41};
    public static final byte[] UWB_CONTROLEE_INFO = {0x42};
    public static final byte[] UWB_SESSION_DATA = {0x43};
    public static final byte[] ACCESS_CONDITIONS = {0x44};
    public static final byte[] ADF_PROVISIONING_CREDENTIAL = {0x45};
    public static final byte[] FIRA_SC_CREDENTIAL = {0x46};
    public static final byte[] EXTENDED_OPTIONS = {0x47};
    public static final byte[] SERVICE_DATA = {0x48};
    public static final byte[] COMMAND_ROUTING_INFORMATION = {0x49};

    public static final byte[] FIRA_SC_CREDENTIAL_ADF_BASE_KEY = {0x50};
    public static final byte[] FIRA_SC_CREDENTIAL_MK_SCX_ENC = {0x51};
    public static final byte[] FIRA_SC_CREDENTIAL_MK_SCX_MAC = {0x52};
    public static final byte[] FIRA_SC_CREDENTIAL_KEY_SCX_PRIV_ENC = {0x53};
    public static final byte[] FIRA_SC_CREDENTIAL_KEY_SCX_PRIV_MAC = {0x54};
    public static final byte[] FIRA_SC_CREDENTIAL_PK_CA_SC2_AUT = {0x55};
    public static final byte[] FIRA_SC_CREDENTIAL_CERT_SC2_AUT = {0x56};
    public static final byte[] FIRA_SC_CREDENTIAL_SK_SC2_AUT = {0x57};
    public static final byte[] FIRA_SC_CREDENTIAL_UWB_RANGING_ROOT_KEY = {0x58};

    /* PACS ADF instance index */
    public static final short PACS_OID = 1;
    public static final short PACS_UWB_CAPABILITIES = 3;
    public static final short PACS_UWB_SESSION_DATA = 4;
    public static final short PACS_UWB_AC_OBJECT = 5;

    /* INS commands */
    public static final byte INS_SELECT = (byte) 0xA4;
    public static final byte INS_SELECT_ADF = (byte) 0xA5;
    public static final byte INS_SWAP_ADF = (byte) 0x40;

    /* AES constants */
    public static final short AES_BLOCK_SIZE = 16;
    public static final byte AES_KEY_SIZE = 16;
    public static final byte AES_GCM_TAG_SIZE = 16;

    /* Memory Buffers */
    public static final short NU_ADF_SLOTS = 8; // one byte
    public static final short HEAP_SIZE = 2048;
    public static final short ADF_SIZE = 1024; // 1k
    public static final short ADF_BUFFER_SIZE = (ADF_SIZE * NU_ADF_SLOTS); // 1k*n
    public static final short ADF_PACS_PROFILE_SIZE = 480; // PACS size rounded to AES_KEY_SIZE

    public static final short NU_LOGICAL_CHANNEL = 8;
}
