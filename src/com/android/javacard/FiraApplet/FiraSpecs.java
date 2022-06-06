package com.android.javacard.FiraApplet;

import javacard.framework.ISO7816;

public class FiraSpecs {
  // FiraApplet Applet Id
  public static final byte[] FIRA_APPLET_AID = {
      (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x08, (byte) 0x67, (byte) 0x46,
      (byte) 0x41, (byte) 0x50, (byte) 0x00};
  public static final byte[] SUS_APPLET_AID = {
      (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x96, (byte) 0x54,
      (byte) 0x53, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
      (byte) 0x04, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00
  };
  // Tag rule bits
  public static final short MANDATORY = (short)0x8000;
  public static final short OPTIONAL = 0;
  public static final short CONDITIONAL = (short) 0x4000;
  public static final short CATEGORY_RULE_MASK = (short)0xC000;
  // Length and count rules
  public static final short EQUAL  = (short) 0;
  public static final short MAX  = (short)0x2000;
  public static final short COUNT = (short)0x1000;
  public static final short UNORDERED = (short)0x0800;
  public static final short ORDERED = 0;
  public static final short LENGTH_RULE_MASK = (short)0x3000;
  public static final short ORDER_RULE_MASK = (short)0x0800;
  public static final short LENGTH_VAL_MASK = (short)0x03FF;

  // Tags related data
  public static final byte EXP_TAG_OFFSET = 0;
  public static final byte EXP_RULE_OFFSET = 1;
  public static final byte EXP_INDEX_OFFSET = 2;
  public static final byte EXP_ROW_SIZE = 3;
  public static final byte INVALID_VALUE = -1;
  // Tag Types
  public static final byte STRUCT_IDX_OFFSET = 0; // structure
  public static final byte ENUM_IDX_OFFSET = 25; // enum
  public static final byte NO_IDX = -1; // bytes
  // Implementation specific limits
  // TODO figure out the actual sizes
  public static final short IMPL_MAX_OID_SIZE = 16;
  public static final short IMPL_MAX_PROV_CRED_SIZE = 68;
  public static final short IMPL_MAX_INSTANCE_ID_SIZE = 16;
  public static final short IMPL_MAX_UWB_CONTROLEE_INFO_SIZE = 250; // Without Capability and regulatory
  public static final short IMPL_MAX_UWB_SESSION_DATA_SIZE = 250;
  public static final short IMPL_MAX_ACCESS_CONDITIONS_SIZE = 32;
  public static final short IMPL_MAX_SERVICE_DATA_SIZE = 128;
  public static final short IMPL_MAX_SWAP_ADF_STATIC_STS_SIZE = 300;
  public static final short IMPL_MAX_SWAP_ADF_SECURE_BLOB_SIZE = 500;
  public static final byte IMPL_INIT_TRANSACTION_MAX_OID_COUNT =1;
  public static final short IMPL_MAX_PROPRIETARY_CMD_SIZE = 512;
  public static final short IMPL_MAX_PROPRIETARY_RESP_SIZE = 512;
  public static final short IMPL_MAX_PROPRIETARY_RESP_NOTIFICATION_SIZE = 128;
  public static final byte IMPL_MAX_PA_LIST_LEN = 1;
  public static final short IMPL_MAX_FIRA_CERT_SIZE = 128;
  public static final short IMPL_MAX_FIRA_CERT_COUNT = 1;
  public static final short IMPL_MAX_STATIC_STS_SLOT_COUNT = 2;
  public static final short IMPL_MAX_CMD_ROUTE_INFO_SIZE = 32;
  public static final short IMPL_MAX_PROV_CRED_COUNT = 1;
  public static final short IMPL_MAX_UWB_CAPABILITY_SIZE = 64;
  public static final short IMPL_MAX_UWB_REGULATORY_SIZE = 64;
  public static final short IMPL_MAX_FIRA_SC_CRED_SIZE = 512;
  public static final short IMPL_FIRA_SC_ASYMMETRIC_KEY_SET = 256;// TODO This is conservative
                                                                  //  estimate as CERT size can
                                                                  //   be quite big if discretionary
                                                                  //   data is big.
  public static final short IMPL_FIRA_SC_SYMETRIC_KEY_SET = 45; // TODO this is specified to be 42 in
                                                                //  FiraApplet Specs it cannot be feasible
  public static final short IMPL_MAX_SECURE_RANGING_INFO_SIZE = 128; // TODO this is bit too much

  // Instructions
  public static final byte INS_CREATE_ADF = (byte)0xE0;
  public static final byte INS_MANAGE_ADF = (byte)0xEA;
  public static final byte INS_IMPORT_ADF = (byte)0xEB;
  public static final byte INS_DELETE_ADF = (byte)0xE4;
  public static final byte INS_SWAP_ADF = (byte)0x40;
  public static final byte INS_TUNNEL = (byte)0x14;
  public static final byte INS_INITIATE_TRANSACTION = (byte)0x12;
  public static final byte INS_DISPATCH = (byte)0xC2;
  public static final byte INS_GET_DATA = (byte)0xCB;
  public static final byte INS_PUT_DATA = (byte)0xDB;
  public static final byte INS_SELECT_ADF = (byte)0xA5;
  public static final byte INS_PERFORM_SECURITY_OPERATION = (byte) 0x2A;
  public static final byte INS_MUTUAL_AUTH = (byte)0x82;
  public static final byte INS_PROVISION_PA_CREDENTIALS = (byte)0xF0;
  public static final byte INS_PROVISION_SD_CREDENTIALS = (byte)0xF1;
  public static final byte INS_PROVISION_SERVICE_APPLET = (byte)0xF2;
  public static final byte INS_SELECT = (byte)0xA4;
  public static final byte INS_GENERAL_AUTH = (byte)0x87;
  public static final byte INS_STORE_DATA = (byte)0xE2;

  // Indexes
  // Structures
  public static final byte STRUCT_ADF_PROVISIONING_CRED_IDX =(byte) 0;
  public static final byte STRUCT_FIRA_SC_SYMMETRIC_KEY_SET_IDX =(byte) 1;
  public static final byte STRUCT_FIRA_SC_ASYMMETRIC_KEY_SET_IDX =(byte) 2;
  public static final byte STRUCT_UWB_CONTROLEE_INFO_IDX =(byte) 3;
  public static final byte STRUCT_UWB_CAPABILITY_IDX =(byte) 4;
  public static final byte STRUCT_UWB_CONTROLEE_PREF_IDX =(byte) 5; // same as UWB Capabilities
  public static final byte STRUCT_UWB_STATIC_RANGING_INFO_IDX =(byte) 6;
  public static final byte STRUCT_UWB_SECURE_RANGING_INFO_IDX =(byte) 7;
  public static final byte STRUCT_UWB_REGULATORY_INFO_IDX =(byte) 8;
  public static final byte STRUCT_UWB_CONFIG_PARAMS_IDX =(byte) 9;
  public static final byte STRUCT_UWB_SESSION_DATA_IDX =(byte) 10;
  public static final byte STRUCT_FIRA_SC_CRED_IDX =(byte) 11;
  public static final byte STRUCT_FIRA_SC_SYMMETRIC_BASE_KEY_IDX =(byte) 12;
  public static final byte STRUCT_FIRA_SC_UWB_RANGING_ROOT_KEY_IDX =(byte) 13;
  public static final byte STRUCT_ADF_PROV_SYMMETRIC_KEY_SET_IDX =(byte) 14;
  public static final byte STRUCT_ADF_PROV_ASYMMETRIC_KEY_SET_IDX =(byte) 15;
  public static final byte STRUCT_SWAP_ADF_SECURE_BLOB_IDX =(byte) 16;
  public static final byte STRUCT_PROPRIETARY_CMD_TEMPLATE_IDX =(byte) 17;
  public static final byte STRUCT_PROPRIETARY_TUNNEL_RESP_TEMPLATE_IDX =(byte) 18;
  public static final byte STRUCT_PROPRIETARY_DISPATCH_RESP_IDX =(byte) 19;
  public static final byte STRUCT_PROPRIETARY_RESP_NOTIFICATION_IDX =(byte) 20;
  public static final byte STRUCT_SWAP_ADF_STATIC_STS_IDX =(byte) 21;
  public static final byte STRUCT_CMD_ROUTE_INFO_IDX =(byte) 22;
  public static final byte STRUCT_CMD_ROUTING_DATA_IDX =(byte) 23;

  public static final byte STRUCT_ACCESS_CONDITIONS_IDX =(byte) 9;

  //enums
  public static final byte ENUM_FIRA_SC_KEY_TYPE_IDX = (byte)(ENUM_IDX_OFFSET+0);
  public static final byte ENUM_ADF_PROV_CH_KEY_TYPE_IDX = (byte)(ENUM_IDX_OFFSET+1);
  public static final byte ENUM_CP_DEVICE_ROLE_IDX = (byte)(ENUM_IDX_OFFSET+2);
  public static final byte ENUM_CP_RANGING_METHOD_IDX = (byte)(ENUM_IDX_OFFSET+3);
  public static final byte ENUM_CP_STS_CONFIG_IDX = (byte)(ENUM_IDX_OFFSET+4);
  public static final byte ENUM_CP_MULTI_NODE_MODE_IDX = (byte)(ENUM_IDX_OFFSET+5);
  public static final byte ENUM_CP_RANGING_TIME_STRUCT_IDX = (byte)(ENUM_IDX_OFFSET+6);
  public static final byte ENUM_CP_SCHEDULED_MODE_IDX = (byte)(ENUM_IDX_OFFSET+7);
  public static final byte ENUM_CP_HOPPING_MODE_IDX = (byte)(ENUM_IDX_OFFSET+8);
  public static final byte ENUM_CP_BLOCK_STRIDING_IDX = (byte)(ENUM_IDX_OFFSET+9);
  public static final byte ENUM_CP_CHANNEL_NUMBER_IDX = (byte)(ENUM_IDX_OFFSET+10);
  public static final byte ENUM_CP_RFRAME_CONFIG_IDX = (byte)(ENUM_IDX_OFFSET+11);
  public static final byte ENUM_CP_CC_CONSTRAINT_LENGTH_IDX = (byte)(ENUM_IDX_OFFSET+12);
  public static final byte ENUM_CP_PRF_MODE_IDX = (byte)(ENUM_IDX_OFFSET+13);
  public static final byte ENUM_CP_PREAMBLE_CODE_INDEX_IDX = (byte)(ENUM_IDX_OFFSET+14);
  public static final byte ENUM_CP_MAC_ADDRESS_MODE_IDX = (byte)(ENUM_IDX_OFFSET+15);
  public static final byte ENUM_CP_KEY_ROTATION_RATE_IDX = (byte)(ENUM_IDX_OFFSET+16);
  public static final byte ENUM_CP_MAC_FCS_TYPE_IDX = (byte)(ENUM_IDX_OFFSET+17);
  public static final byte ENUM_UWB_CONFIG_AVAILABLE_IDX = (byte)(ENUM_IDX_OFFSET+18);
  public static final byte ENUM_FIRA_SC_SYMMETRIC_BASE_KEY_CH_ID_IDX = (byte)(ENUM_IDX_OFFSET+19);
  public static final byte ENUM_FIRA_SC_KEY_USAGE_IDX = (byte)(ENUM_IDX_OFFSET+20);
  public static final byte ENUM_ADF_PROV_SYMMETRIC_CH_ID_IDX = (byte)(ENUM_IDX_OFFSET+21);
  public static final byte ENUM_ADF_PROV_ASYMMETRIC_CH_ID_IDX = (byte)(ENUM_IDX_OFFSET+22);
  public static final byte ENUM_FIRA_SC_SYMMETRIC_CH_ID_IDX = (byte)(ENUM_IDX_OFFSET+23);
  public static final byte ENUM_FIRA_SC_ASYMMETRIC_CH_ID_IDX = (byte)(ENUM_IDX_OFFSET+24);
  public static final byte ENUM_PROPRIETARY_DISPATCH_RESP_STATUS_IDX = (byte)(ENUM_IDX_OFFSET+25);
  public static final byte ENUM_PROPRIETARY_RESP_NOTIFICATION_ID_IDX = (byte)(ENUM_IDX_OFFSET+26);
  public static final byte ENUM_CMD_ROUTING_TARGET_IDX = (byte)(ENUM_IDX_OFFSET+27);
  public static final byte ENUM_PA_CRED_TYPE_IDX = (byte)(ENUM_IDX_OFFSET+28);

  // Tags for Provisioning
  public static final short TAG_ADD_REPLACE_PA_CREDENTIALS = (short)0x1000;
  public static final short TAG_ERASE_PA_CREDENTIALS =(short) 0x1001;
  public static final short TAG_PA_RECORD = (short)0xB0; //custom tag
  public static final short TAG_MASTER_KEY =(short) 0x80; // custom tag
  public static final short TAG_DEVICE_UID =(short) 0x81; // custom tag
  public static final short TAG_APPLET_SECRET =(short) 0xB2; // custom tag
  public static final short TAG_PA_CRED_PA_ID =(short) 0x41;
  public static final short TAG_PA_CRED_PA_CRED_TYPE =(short) 0x42;
  public static final short TAG_PA_CRED_PA_CREDS =(short) 0x43;

  // Select Adf related tags and data
  public static final short TAG_RANDOM_DATA_1_2 =(short) 0x85;
  public static final short TAG_DIVERSIFIER =(short) 0xCF;
  public static final byte[] SELECT_ADF_ALGORITHM_INFO = {(byte)0xCD, 0x01,0x09};

  //Instruction - Create ADF
  public static final short TAG_OID = (short)0x06;
  public static final short TAG_ADF_PROVISIONING_CRED = (short)0xBF50;
  public static final short TAG_STORED_ADF_PROVISIONING_CRED = (short)0xBF7F; // This is custom tag
  public static final short[] DATA_CREATE_ADF = {
      TAG_OID, (short)(MANDATORY | MAX | IMPL_MAX_OID_SIZE),NO_IDX,
      TAG_ADF_PROVISIONING_CRED, (short)(UNORDERED|CONDITIONAL|COUNT|IMPL_MAX_PROV_CRED_COUNT),STRUCT_ADF_PROVISIONING_CRED_IDX,
  };
  public static final short TAG_ADF_PROV_SEC_CH_ID =(short) 0x80;
  public static final short TAG_ADF_PROV_SEC_KEY_TYPE =(short) 0x81;
  public static final short TAG_ADF_PROV_SEC_CH_KVN =(short) 0x83;
  public static final short TAG_ADF_PROV_SYM_ENC_KEY =(short) 0x84;
  public static final short TAG_ADF_PROV_SYM_MAC_KEY =(short) 0x85;
  public static final short TAG_ADF_PROV_CA_PUB_KEY =(short) 0x84;
  public static final short TAG_ADF_PROV_SYMMETRIC_KEY_SET =(short) 0xB9;
  public static final short TAG_ADF_PROV_ASYMMETRIC_KEY_SET =(short) 0xBA;

  public static final short[] STRUCT_ADF_PROVISIONING_CRED ={
      TAG_ADF_PROV_SYMMETRIC_KEY_SET, (short)(CONDITIONAL | MAX | 42),STRUCT_ADF_PROV_SYMMETRIC_KEY_SET_IDX,
      TAG_ADF_PROV_ASYMMETRIC_KEY_SET, (short)(CONDITIONAL |MAX | 68),STRUCT_ADF_PROV_ASYMMETRIC_KEY_SET_IDX,
  };
  public static final short[] STRUCT_ADF_PROV_SYMMETRIC_KEY_SET ={
      TAG_ADF_PROV_SEC_CH_ID, (short)(MANDATORY | 1),ENUM_ADF_PROV_SYMMETRIC_CH_ID_IDX,
      TAG_ADF_PROV_SEC_CH_KVN, (short)(MANDATORY | 1),NO_IDX,
      TAG_ADF_PROV_SYM_ENC_KEY, (short)(MANDATORY | 16),NO_IDX,
      TAG_ADF_PROV_SYM_MAC_KEY, (short) (MANDATORY | 16),NO_IDX,
  };
  public static final short[] STRUCT_ADF_PROV_ASYMMETRIC_KEY_SET ={
      TAG_ADF_PROV_SEC_CH_ID, (short)(MANDATORY | 1),ENUM_ADF_PROV_ASYMMETRIC_CH_ID_IDX,
      TAG_ADF_PROV_SEC_KEY_TYPE, (short)(MANDATORY | 1),ENUM_ADF_PROV_CH_KEY_TYPE_IDX,
      TAG_ADF_PROV_SEC_CH_KVN, (short)(MANDATORY | 1),NO_IDX,
      TAG_ADF_PROV_CA_PUB_KEY, (short) (MANDATORY |MAX|65),NO_IDX,
  };
  public static final short VAL_SC1 =(short) 1;
  public static final short VAL_SC1_PRIVACY_KEY_SET =(short) 0x81;
  public static final short VAL_SC2 =(short) 2;
  public static final short VAL_SC2_PRIVACY_KEY_SET =(short) 0x82;
  public static final short VAL_GP_SCP11c =(short) 4;

  public static final short[] ENUM_ADF_PROV_SYMMETRIC_CH_ID ={
      VAL_SC1,
      VAL_SC2,
  };
  public static final short[] ENUM_ADF_PROV_ASYMMETRIC_CH_ID ={
      VAL_SC2,
      VAL_GP_SCP11c,
  };
  public static final short VAL_ECC_NIST_P_256 = (short) 0x01;
  public static final short[] ENUM_ADF_PROV_CH_KEY_TYPE ={
      VAL_ECC_NIST_P_256,
  };

  // Instruction - Manage Adf
  // DO Tag Ids
  //TODO both FIRA SC Cred and ADF Prov Credentials have same tag number. Is this correct?
  public static final short TAG_FIRA_SC_CRED = (short)0xBF50;
  public static final short TAG_ACCESS_CONDITIONS = (short)0xBF55;// TODO should we support this? It
                                                                  //  does not make any sense of doing this.
                                                                  //  We can make default policy i.e. all
                                                                  //  writes and reads to controlee info will
                                                                  //  be secure. The UWB Capabilities and
                                                                  //  regulatory info can only be written in local
                                                                  //  secure way. For Service Data we can
                                                                  //  support this tag
  public static final short TAG_UWB_CONTROLEE_INFO =(short) 0xBF70;
  public static final short TAG_CMD_ROUTE_INFO =(short) 0xBF72;
  public static final short TAG_UWB_SESSION_DATA =(short) 0xBF78;
  public static final short TAG_INSTANCE_ID =(short) 0x4F;
  public static final short TAG_EXTENDED_OPTIONS =(short) 0x9C;
  public static final short TAG_APP_DATA_OBJECTS = (short) 0xBF76;
  //TODO confirm that service data is same as app data objects
  public static final short TAG_SERVICE_DATA = TAG_APP_DATA_OBJECTS;

  //  ADF structure
  public static final short[] STRUCT_ADF = {
      TAG_OID, (short)(MANDATORY|MAX|IMPL_MAX_OID_SIZE),NO_IDX,
      TAG_INSTANCE_ID, (short)(CONDITIONAL|MAX|IMPL_MAX_INSTANCE_ID_SIZE),NO_IDX,
      TAG_UWB_CONTROLEE_INFO, (short)(CONDITIONAL| MAX | IMPL_MAX_UWB_CONTROLEE_INFO_SIZE),STRUCT_UWB_CONTROLEE_INFO_IDX,
      TAG_UWB_SESSION_DATA,(short)(CONDITIONAL| MAX | IMPL_MAX_UWB_SESSION_DATA_SIZE), STRUCT_UWB_SESSION_DATA_IDX,
      TAG_ACCESS_CONDITIONS, (short)(OPTIONAL|MAX|IMPL_MAX_ACCESS_CONDITIONS_SIZE), NO_IDX,
      TAG_ADF_PROVISIONING_CRED, (short)(CONDITIONAL|MAX|IMPL_MAX_PROV_CRED_SIZE), STRUCT_ADF_PROVISIONING_CRED_IDX,
      TAG_FIRA_SC_CRED, (short)(MANDATORY|UNORDERED|MAX|IMPL_MAX_FIRA_SC_CRED_SIZE),STRUCT_FIRA_SC_CRED_IDX,
      TAG_EXTENDED_OPTIONS,(short)(OPTIONAL|4),NO_IDX,
      TAG_SERVICE_DATA, (short)(OPTIONAL|MAX|IMPL_MAX_SERVICE_DATA_SIZE),NO_IDX,
      TAG_CMD_ROUTE_INFO, (short)(OPTIONAL|MAX|IMPL_MAX_CMD_ROUTE_INFO_SIZE),STRUCT_CMD_ROUTE_INFO_IDX,
  };

  public static final short TAG_CMD_ROUTING_TARGET = (short) 0x80;
  public static final short TAG_CMD_ROUTING_DATA = (short) 0x81;
  public static final short TAG_SERVICE_APPLET_ID = (short) 0x82; // TODO this is a custom tag
  public static final short[] STRUCT_CMD_ROUTE_INFO = {
      TAG_CMD_ROUTING_TARGET, (short)(MANDATORY|1), ENUM_CMD_ROUTING_TARGET_IDX,
      TAG_CMD_ROUTING_DATA, (short)(MANDATORY|MAX|290),STRUCT_CMD_ROUTING_DATA_IDX,
      TAG_SERVICE_APPLET_ID, (short)(OPTIONAL | MAX | 16), NO_IDX,
  };
  public static final short TAG_CMD_ROUTE_SESSION_ID =(short) 0x80;
  public static final short[] STRUCT_CMD_ROUTING_DATA = {
      TAG_OID, (short)(MANDATORY | MAX | IMPL_MAX_OID_SIZE), NO_IDX,
      TAG_CMD_ROUTE_SESSION_ID, (short)(OPTIONAL|4), NO_IDX,
      TAG_CMD_ROUTING_DATA, (short)(OPTIONAL|MAX|256),NO_IDX, //TODO for every service
                                                              // applet this can be different
  };

  public static final short VAL_APP =(short) 0x00;
  public static final short VAL_SERVICE_APPLET =(short) 0x01;

  public static final short[] ENUM_CMD_ROUTING_TARGET = {
    VAL_APP, VAL_SERVICE_APPLET,
  };
  public static final short INS_MANAGE_ADF_FINISH_P1 =(short) 0x00;
  public static final short INS_MANAGE_ADF_CONTINUE_P1 =(short) 0x01;
  public static final short[] DATA_MANAGE_ADF_CMD = {
      TAG_UWB_CONTROLEE_INFO, (short)(CONDITIONAL|MAX|IMPL_MAX_UWB_CONTROLEE_INFO_SIZE),STRUCT_UWB_CONTROLEE_INFO_IDX, //TODO Why this is required in Manage ADF
      TAG_ACCESS_CONDITIONS, (short)(OPTIONAL|MAX|IMPL_MAX_ACCESS_CONDITIONS_SIZE),NO_IDX,
      TAG_FIRA_SC_CRED, (short)(CONDITIONAL|UNORDERED|MAX|IMPL_MAX_FIRA_SC_CRED_SIZE), STRUCT_FIRA_SC_CRED_IDX,// TODO Why This is conditional in FiraApplet Specs
      TAG_APP_DATA_OBJECTS, (short)(OPTIONAL|MAX|IMPL_MAX_SERVICE_DATA_SIZE),NO_IDX,
      TAG_INSTANCE_ID, (short)(OPTIONAL|MAX|IMPL_MAX_INSTANCE_ID_SIZE),NO_IDX,
      TAG_EXTENDED_OPTIONS, (short)(OPTIONAL|4),NO_IDX,
      TAG_CMD_ROUTE_INFO, (short)(OPTIONAL |MAX| IMPL_MAX_CMD_ROUTE_INFO_SIZE), STRUCT_CMD_ROUTE_INFO_IDX,
  };

  // Controlee Info - all the bit masks are treated as byte blob and not ENUMs.
  public static final short TAG_UWB_CAPABILITY = (short) 0xA3;
  public static final short TAG_FIRA_PHY_VERSION_RANGE =(short) 0x80;
  public static final short TAG_FIRA_MAC_VERSION_RANGE =(short) 0x81;
  public static final short TAG_DEVICE_ROLES = (short) 0x82;
  public static final short TAG_RANGING_METHOD = (short) 0x83;
  public static final short TAG_STS_CONFIG = (short) 0x84;
  public static final short TAG_MULTI_NODE_MODE = (short) 0x85;
  public static final short TAG_RANGING_TIME_STRUCT = (short) 0x86;
  public static final short TAG_SCHEDULED_MODE = (short) 0x87;
  public static final short TAG_HOPPING_MODE = (short) 0x88;
  public static final short TAG_BLOCK_STRIDING = (short) 0x89;
  public static final short TAG_UWB_INITIATION_TIME = (short) 0x8A;
  public static final short TAG_CHANNELS = (short) 0x8B;
  public static final short TAG_RFRAME_CONFIG = (short) 0x8C;
  public static final short TAG_CC_CONSTRAINT_LENGTH = (short) 0x8D ;
  public static final short TAG_BPRF_PARAMETER_SETS = (short) 0x8E;
  public static final short TAG_HPRF_PARAMETER_SETS = (short) 0x8F;
  public static final short TAG_AOA_SUPPORT = (short) 0x90;
  public static final short TAG_EXTENDED_MAC_ADDRESS = (short) 0x91;
  // TODO FiraApplet Specs does not specify whether some of the tags are mandatory. It seems that phy
  //  version and mac version are mandatory. This needs to be ascertained.
  public static final short[] STRUCT_UWB_CAPABILITY = {
      TAG_FIRA_PHY_VERSION_RANGE, (short)(MANDATORY | 4), NO_IDX,
      TAG_FIRA_MAC_VERSION_RANGE, (short)(MANDATORY | 4), NO_IDX,
      TAG_DEVICE_ROLES, (short)(OPTIONAL | 1), NO_IDX,
      TAG_RANGING_METHOD, (short)(OPTIONAL | 1), NO_IDX,
      TAG_STS_CONFIG,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_MULTI_NODE_MODE,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_RANGING_TIME_STRUCT,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_SCHEDULED_MODE,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_HOPPING_MODE,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_BLOCK_STRIDING,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_UWB_INITIATION_TIME,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNELS,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_RFRAME_CONFIG,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CC_CONSTRAINT_LENGTH,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_BPRF_PARAMETER_SETS,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_HPRF_PARAMETER_SETS,  (short)(OPTIONAL | 5), NO_IDX,
      TAG_AOA_SUPPORT,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_EXTENDED_MAC_ADDRESS,  (short)(OPTIONAL | 1), NO_IDX,
  };
  public static final short TAG_UWB_CONTROLEE_PREF = (short) 0xA7;
  public static final short[] STRUCT_UWB_CONTROLEE_PREF = {
      TAG_DEVICE_ROLES, (short)(OPTIONAL | 1), NO_IDX,
      TAG_RANGING_METHOD, (short)(OPTIONAL | 1), NO_IDX,
      TAG_STS_CONFIG,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_MULTI_NODE_MODE,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_RANGING_TIME_STRUCT,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_SCHEDULED_MODE,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_HOPPING_MODE,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_BLOCK_STRIDING,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_UWB_INITIATION_TIME,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNELS,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_RFRAME_CONFIG,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CC_CONSTRAINT_LENGTH,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_BPRF_PARAMETER_SETS,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_HPRF_PARAMETER_SETS,  (short)(OPTIONAL | 5), NO_IDX,
      TAG_AOA_SUPPORT,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_EXTENDED_MAC_ADDRESS,  (short)(OPTIONAL | 1), NO_IDX,
  };
  public static final short TAG_UWB_REGULATORY_INFO = (short) 0xA6;
  public static final short TAG_INFORMATION_SOURCE = (short) 0x80 ;
  public static final short TAG_OUTDOOR_PERMITTED = (short) 0x81;
  public static final short TAG_COUNTRY_CODE = (short) 0x82;
  public static final short TAG_TIMESTAMP = (short) 0x83;
  public static final short TAG_CHANNEL5 = (short) 0x84;
  public static final short TAG_CHANNEL6 = (short) 0x85;
  public static final short TAG_CHANNEL7 = (short) 0x86;
  public static final short TAG_CHANNEL8 = (short) 0x87;
  public static final short TAG_CHANNEL9 = (short) 0x88;
  public static final short TAG_CHANNEL10 = (short) 0x89;
  public static final short TAG_CHANNEL11 = (short) 0x8A;
  public static final short TAG_CHANNEL12 = (short) 0x8B;
  public static final short TAG_CHANNEL13 = (short) 0x8C;
  public static final short TAG_CHANNEL14 = (short) 0x8D;
  public static final short[] STRUCT_UWB_REGULATORY_INFO = {
      TAG_INFORMATION_SOURCE,  (short)(MANDATORY | 1), NO_IDX,
      TAG_OUTDOOR_PERMITTED,  (short)(MANDATORY | 1), NO_IDX,
      TAG_COUNTRY_CODE,  (short)(MANDATORY | 2), NO_IDX,
      TAG_TIMESTAMP,  (short)(MANDATORY | 4), NO_IDX,
      TAG_CHANNEL5,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL6,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL7,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL8,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL9,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL10,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL11,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL12,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL13,  (short)(OPTIONAL | 1), NO_IDX,
      TAG_CHANNEL14,  (short)(OPTIONAL | 1), NO_IDX,
  };

  public static final short TAG_UWB_STATIC_RANGING_INFO =(short) 0xA4;
  public static final short TAG_VENDOR_ID =(short) 0x80;
  public static final short TAG_STATIC_STS_IV =(short) 0x81;
  public static final short[] STRUCT_UWB_STATIC_RANGING_INFO = {
      TAG_VENDOR_ID, (short)(MANDATORY | 2),NO_IDX,
      TAG_STATIC_STS_IV, (short)(MANDATORY | 6),NO_IDX,
  };

  public static final short TAG_UWB_SECURE_RANGING_INFO =(short) 0xA5;
  public static final short TAG_SESSION_KEY_INFO =(short) 0x80;
  public static final short TAG_RESPONDER_SPECIFIC_SUB_SESSION_KEY_INFO =(short) 0x81;
  public static final short TAG_SUS_ADDITIONAL_PARAMS =(short) 0x82;
  public static final short SESSION_KEY_INFO_MAX_SIZE =(short) 32;
  public static final short RESPONDER_SPECIFIC_SUB_SESSION_KEY_INFO_MAX_SIZE =(short) 32;
  public static final short SUS_ADDITIONAL_PARAMS_MAX_SIZE =(short) 128;// TODO check the maximum value
  public static final short[] STRUCT_UWB_SECURE_RANGING_INFO = {
      TAG_SESSION_KEY_INFO, (short)(CONDITIONAL |MAX| SESSION_KEY_INFO_MAX_SIZE),NO_IDX,
      TAG_RESPONDER_SPECIFIC_SUB_SESSION_KEY_INFO, (short)(CONDITIONAL | MAX| RESPONDER_SPECIFIC_SUB_SESSION_KEY_INFO_MAX_SIZE),NO_IDX,
      TAG_SUS_ADDITIONAL_PARAMS, (short)(CONDITIONAL |MAX| SUS_ADDITIONAL_PARAMS_MAX_SIZE),NO_IDX,
  };

  public static final short TAG_UWB_CONTROLEE_INFO_VERSION =(short) 0x80;
  public static final short[] STRUCT_UWB_CONTROLEE_INFO = {
      TAG_UWB_CONTROLEE_INFO_VERSION, (short)(MANDATORY | 2), NO_IDX,
      TAG_UWB_CAPABILITY, (short)(CONDITIONAL| MAX| IMPL_MAX_UWB_CAPABILITY_SIZE), STRUCT_UWB_CAPABILITY_IDX,
      TAG_UWB_CONTROLEE_PREF, (short)(OPTIONAL|MAX|IMPL_MAX_UWB_CAPABILITY_SIZE), STRUCT_UWB_CONTROLEE_PREF_IDX,
      TAG_UWB_STATIC_RANGING_INFO, (short)(OPTIONAL|MAX|16), STRUCT_UWB_STATIC_RANGING_INFO_IDX,
      TAG_UWB_SECURE_RANGING_INFO, (short)(OPTIONAL|MAX|IMPL_MAX_SECURE_RANGING_INFO_SIZE), STRUCT_UWB_SECURE_RANGING_INFO_IDX,
      TAG_UWB_REGULATORY_INFO, (short)(OPTIONAL|MAX|IMPL_MAX_UWB_REGULATORY_SIZE), STRUCT_UWB_REGULATORY_INFO_IDX,
  };

  // FiraApplet Secure Channel Credentials
  public static final short TAG_FIRA_SC_CH_ID =(short) 0x80;
  public static final short TAG_FIRA_SC_SYMMETRIC_KEY_SET =(short) 0xB9;
  public static final short TAG_FIRA_SC_ASYMMETRIC_KEY_SET =(short) 0xBA;
  public static final short TAG_FIRA_SC_SYMMETRIC_BASE_KEY =(short) 0xB8;
  public static final short TAG_FIRA_SC_UWB_RANGING_ROOT_KEY =(short) 0xBB;
  // TODO it is not clear whether FiraApplet Cred is un ordered and the element tags are mandatory or not
  // TODO we assume that it will be unordered with all the elements conditional
  public static final short[] STRUCT_FIRA_SC_CRED ={
      TAG_FIRA_SC_SYMMETRIC_KEY_SET,(short)(CONDITIONAL | MAX | IMPL_FIRA_SC_SYMETRIC_KEY_SET),STRUCT_FIRA_SC_SYMMETRIC_KEY_SET_IDX,
      TAG_FIRA_SC_ASYMMETRIC_KEY_SET, (short)(CONDITIONAL |MAX | IMPL_FIRA_SC_ASYMMETRIC_KEY_SET),STRUCT_FIRA_SC_ASYMMETRIC_KEY_SET_IDX,
      TAG_FIRA_SC_SYMMETRIC_BASE_KEY, (short)(CONDITIONAL |MAX | 32), STRUCT_FIRA_SC_SYMMETRIC_BASE_KEY_IDX,
      TAG_FIRA_SC_UWB_RANGING_ROOT_KEY, (short)(CONDITIONAL |MAX | 64), STRUCT_FIRA_SC_UWB_RANGING_ROOT_KEY_IDX,
  };
  public static final short TAG_FIRA_SC_SYMMETRIC_BASE_KEY_CH_ID =(short) 0x80;
  public static final short TAG_FIRA_SC_KEY_USAGE =(short) 0x82;
  public static final short TAG_FIRA_SC_SYMMETRIC_BASE_KEY_KVN =(short) 0x83;
  public static final short TAG_FIRA_SC_SYMMETRIC_BASE_KEY_VALUE =(short) 0x84;

  public static final short[] STRUCT_FIRA_SC_SYMMETRIC_BASE_KEY ={
      TAG_FIRA_SC_SYMMETRIC_BASE_KEY_CH_ID, (short)(MANDATORY | 1), ENUM_FIRA_SC_SYMMETRIC_BASE_KEY_CH_ID_IDX,
      TAG_FIRA_SC_KEY_USAGE, (short)(OPTIONAL | 1), ENUM_FIRA_SC_KEY_USAGE_IDX,
      TAG_FIRA_SC_SYMMETRIC_BASE_KEY_KVN, (short)(MANDATORY | 1), NO_IDX,
      TAG_FIRA_SC_SYMMETRIC_BASE_KEY_VALUE, (short)(MANDATORY | 16), NO_IDX,
  };
  public static final short TAG_FIRA_SC_UWB_RANGING_ROOT_KEY_KVN =(short) 0x83;
  public static final short TAG_FIRA_SC_UWB_RANGING_ROOT_KEY_VAL =(short) 0x84;
  public static final short TAG_FIRA_SC_UWB_RANGING_ROOT_KEY_LBL =(short) 0x85;

  public static final short[] STRUCT_FIRA_SC_UWB_RANGING_ROOT_KEY ={
      TAG_FIRA_SC_UWB_RANGING_ROOT_KEY_KVN, (short)(MANDATORY | 1), NO_IDX,
      TAG_FIRA_SC_UWB_RANGING_ROOT_KEY_VAL, (short)(MANDATORY | MAX |32), NO_IDX,
      TAG_FIRA_SC_UWB_RANGING_ROOT_KEY_LBL, (short)(MANDATORY |4), NO_IDX,
  };
  // KVN
  public static final short TAG_FIRA_SC_KVN = 0x83;
  public static final byte FIRA_SC_KVN_LEN = 1;

  // Symmetric key and mac
  public static final short TAG_FIRA_SC_SYM_ENC_KEY =(short) 0x84; //MK_SCx_ENC
  public static final short TAG_FIRA_SC_SYM_MAC_KEY = (short) 0x85; //MK_SCx_MAC
  public static final short[] STRUCT_FIRA_SC_SYMMETRIC_KEY_SET ={
      TAG_FIRA_SC_CH_ID, (short)(MANDATORY | 1),ENUM_FIRA_SC_SYMMETRIC_CH_ID_IDX,
      TAG_FIRA_SC_KEY_USAGE, (short)(OPTIONAL | 1), ENUM_FIRA_SC_KEY_USAGE_IDX,
      TAG_FIRA_SC_KVN, (short)(MANDATORY | 1),NO_IDX,
      TAG_FIRA_SC_SYM_ENC_KEY, (short)(MANDATORY | 16),NO_IDX,
      TAG_FIRA_SC_SYM_MAC_KEY, (short) (MANDATORY | 16),NO_IDX,
  };

  // Asymmetric key
  public static final short TAG_FIRA_SC_ADF_CA_PUB_KEY =(short) 0x84;
  public static final short TAG_FIRA_SC_KEY_TYPE =(short) 0x81;
  public static final short TAG_FIRA_SC_ADF_CA_PUB_CERT =(short) 0x85;
  public static final short TAG_FIRA_SC_ADF_PRIVATE_KEY =(short) 0x86;

  public static final short[] STRUCT_FIRA_SC_ASYMMETRIC_KEY_SET ={
      TAG_FIRA_SC_CH_ID, (short)(MANDATORY | 1),ENUM_FIRA_SC_ASYMMETRIC_CH_ID_IDX,
      TAG_FIRA_SC_KEY_TYPE, (short)(MANDATORY | 1),ENUM_FIRA_SC_KEY_TYPE_IDX,
      TAG_FIRA_SC_KEY_USAGE, (short)(OPTIONAL | 1), ENUM_FIRA_SC_KEY_USAGE_IDX,
      TAG_FIRA_SC_KVN, (short)(MANDATORY | 1),NO_IDX,
      TAG_FIRA_SC_ADF_CA_PUB_KEY, (short) (MANDATORY |MAX|65),NO_IDX,
      TAG_FIRA_SC_ADF_CA_PUB_CERT, (short)(MANDATORY|MAX|IMPL_MAX_FIRA_CERT_SIZE),NO_IDX,
      TAG_FIRA_SC_ADF_PRIVATE_KEY, (short)(MANDATORY|MAX|32), NO_IDX,
  };
  public static final byte VAL_FIRA_KEY_USAGE_REMOTE =(byte) 0;
  public static final byte VAL_FIRA_KEY_USAGE_LOCAL = (byte) 1;
  public static final short[] ENUM_FIRA_SC_KEY_USAGE = {
      VAL_FIRA_KEY_USAGE_REMOTE,
      VAL_FIRA_KEY_USAGE_LOCAL,
  };
  public static final short[] ENUM_FIRA_SC_KEY_TYPE = {
      VAL_ECC_NIST_P_256,
  };;
  public static final short[] ENUM_FIRA_SC_SYMMETRIC_CH_ID ={
      VAL_SC1,
      VAL_SC1_PRIVACY_KEY_SET,
      VAL_SC2,
      VAL_SC2_PRIVACY_KEY_SET,
  };
  public static final short[] ENUM_FIRA_SC_ASYMMETRIC_CH_ID ={
      VAL_SC2,
  };
  public static final short[] ENUM_FIRA_SC_SYMMETRIC_BASE_KEY_CH_ID = {
      VAL_SC1,
      VAL_SC2,
  };

  // Instruction - Delete Adf
  public static final short[] DATA_DELETE_ADF_CMD = {
    TAG_OID, (short)(MANDATORY | MAX | IMPL_MAX_OID_SIZE), NO_IDX,
  };

  // Instruction - Import Adf
  //TODO check this where this is required to be used
  public static final short TAG_MANAGE_ADF_CMD_ROUTE_INFO =(short) 0x0C;
  public static final short TAG_IMPORT_ADF_ACCESS_CONDITIONS = (short)0xDF70;// TODO why this is different from access conditions tag in adf
  public static final short TAG_SWAP_ADF_SECURE_BLOB = (short)0xDF51;
  public static final short[] DATA_IMPORT_ADF_CMD = {
      TAG_OID, (short)(OPTIONAL | MAX | IMPL_MAX_OID_SIZE), NO_IDX,
      //TODO confirm that this tag is required because then we have to store this in the blob
      TAG_UWB_CONTROLEE_INFO, (short)(OPTIONAL | MAX | IMPL_MAX_UWB_CONTROLEE_INFO_SIZE),STRUCT_UWB_CONTROLEE_INFO_IDX,
      TAG_IMPORT_ADF_ACCESS_CONDITIONS, (short)(CONDITIONAL | MAX | IMPL_MAX_ACCESS_CONDITIONS_SIZE),NO_IDX,
      TAG_FIRA_SC_CRED, (short) (MANDATORY |UNORDERED|MAX|IMPL_MAX_FIRA_SC_CRED_SIZE),STRUCT_FIRA_SC_CRED_IDX,
      TAG_EXTENDED_OPTIONS, (short) (OPTIONAL | 4),NO_IDX,
  };

  // Instruction - Swap ADF
  public static final byte INS_P1_SWAP_ADF_OP_ACQUIRE =(byte) 0x00;
  public static final byte INS_P1_SWAP_ADF_OP_RELEASE =(byte) 0x01;
  // TODO confirm whether this needs to be supported.
  public static final short TAG_SWAP_ADF_STATIC_STS = (short)0xDF50;
  public static final short[] DATA_SWAP_ADF_ACQUIRE_CMD = {
      //TODO not supporting static sts
      //      TAG_SWAP_ADF_STATIC_STS, (short) (CONDITIONAL | MAX | IMPL_MAX_SWAP_ADF_STATIC_STS_SIZE), STRUCT_SWAP_ADF_STATIC_STS_IDX,
      TAG_SWAP_ADF_SECURE_BLOB, (short) (CONDITIONAL | MAX | IMPL_MAX_SWAP_ADF_SECURE_BLOB_SIZE), NO_IDX,
  };

  public static final short[] STRUCT_SWAP_ADF_STATIC_STS = {
      TAG_OID, (short) (MANDATORY | MAX | IMPL_MAX_OID_SIZE), NO_IDX,
      TAG_UWB_CONTROLEE_INFO, (short) (MANDATORY | MAX | IMPL_MAX_UWB_CONTROLEE_INFO_SIZE), STRUCT_UWB_CONTROLEE_INFO_IDX,
  };

  // This structure is used to decode the secure blob which is created by the import adf command.
  // TODO SWAP ADF Release will have slot identifier as a payload.
  //  Confirm that this will not be a BER TLV object.
  //  Also, in FiraApplet Specs most of the tags are required to be mandatory but import adf have them as
  //  optional which does not make sense. So the implementation is taking liberal approach.
  //  Also, for both import adf and swap adf commands, we enforce order although it is not clear from
  //  the specs whether they are ordered or not,
  public static final short[] STRUCT_SWAP_ADF_SECURE_BLOB = {
      TAG_UWB_CONTROLEE_INFO, (short) (OPTIONAL | MAX | IMPL_MAX_UWB_CONTROLEE_INFO_SIZE),STRUCT_UWB_CONTROLEE_INFO_IDX,
      TAG_IMPORT_ADF_ACCESS_CONDITIONS, (short) (CONDITIONAL | MAX | IMPL_MAX_ACCESS_CONDITIONS_SIZE), NO_IDX,
      TAG_FIRA_SC_CRED, (short) (MANDATORY |UNORDERED|MAX | IMPL_MAX_FIRA_SC_CRED_SIZE), STRUCT_FIRA_SC_CRED_IDX,
      TAG_EXTENDED_OPTIONS, (short) (OPTIONAL | 4), NO_IDX,
      TAG_OID, (short) (MANDATORY | MAX | IMPL_MAX_OID_SIZE), NO_IDX,
  };

  // Instruction - Initiate Transaction
  // TODO Currently only unicast is supported
  public static final byte INS_P1_INITIATE_TRANSACTION_UNICAST =(byte) 0x00;
  public static final byte INS_P1_INITIATE_TRANSACTION_MULTICAST =(byte) 0x01;
  public static final short TAG_INIT_TRANS_UWB_SESSION_ID =(short) 0x80;
  public static final short[] DATA_INITIATE_TRANSACTION = {
      // TODO uncomment when multicast needs to be supported - controller role
      //TAG_INIT_TRANS_UWB_SESSION_ID, (short)(CONDITIONAL | 4), NO_IDX,
      TAG_OID, (short)(MANDATORY | MAX | IMPL_INIT_TRANSACTION_MAX_OID_COUNT*IMPL_MAX_OID_SIZE), NO_IDX,
      // TODO uncomment when multicast needs to be supported - controller role
      //TAG_OID, (short)(OPTIONAL | MAX | IMPL_INIT_TRANSACTION_MAX_OID_COUNT*IMPL_MAX_OID_SIZE), NO_IDX,
      //TAG_OID, (short)(OPTIONAL | MAX | IMPL_INIT_TRANSACTION_MAX_OID_COUNT*IMPL_MAX_OID_SIZE), NO_IDX,
      //TAG_OID, (short)(OPTIONAL | MAX | IMPL_INIT_TRANSACTION_MAX_OID_COUNT*IMPL_MAX_OID_SIZE), NO_IDX,
  };
  // Tunnel
  public static final short TAG_PROPRIETARY_CMD_TEMPLATE =(short) 0x70;
  public static final short TAG_PROPRIETARY_CMD_DATA =(short) 0x81;
  public static final short[] DATA_TUNNEL = {
      TAG_PROPRIETARY_CMD_TEMPLATE,(short) (MANDATORY | MAX | IMPL_MAX_PROPRIETARY_CMD_SIZE), STRUCT_PROPRIETARY_CMD_TEMPLATE_IDX,
  };
  public static final short[] STRUCT_PROPRIETARY_CMD_TEMPLATE = {
      TAG_PROPRIETARY_CMD_DATA, (short)(MANDATORY | MAX | IMPL_MAX_PROPRIETARY_CMD_SIZE), NO_IDX,
  };
  public static final short TAG_PROPRIETARY_RESP_TEMPLATE =(short) 0x71;
  public static final short TAG_PROPRIETARY_RESP_STATUS =(short) 0x80;
  public static final short TAG_PROPRIETARY_RESP_DATA =(short) 0x81;
  /*// TODO currently this is not used but in future if the responses needs to be validated then
  //  this can be used.
  public static final short[] DATA_TUNNEL_RESP = {
      TAG_PROPRIETARY_RESP_TEMPLATE, MANDATORY, STRUCT_PROPRIETARY_TUNNEL_RESP_TEMPLATE_IDX,
  };
   */
  public static final short[] STRUCT_PROPRIETARY_TUNNEL_RESP_TEMPLATE = {
      TAG_PROPRIETARY_RESP_STATUS, (short)(MANDATORY | 1),NO_IDX,
      TAG_PROPRIETARY_RESP_DATA, (short)(OPTIONAL | MAX | IMPL_MAX_PROPRIETARY_RESP_SIZE), NO_IDX,
  };

  // Instruction - Dispatch
  public static final short TAG_PROPRIETARY_RESP_NOTIFICATION =(short) 0xE1;
  public static final short TAG_PROPRIETARY_RESP_NOTIFICATION_FMT =(short) 0x80;
  public static final short TAG_PROPRIETARY_RESP_NOTIFICATION_ID =(short) 0x81;
  public static final short TAG_PROPRIETARY_RESP_NOTIFICATION_DATA =(short) 0x82;

  public static final short[] DATA_DISPATCH_CMD = {
      TAG_PROPRIETARY_CMD_TEMPLATE, (short)(MANDATORY|MAX| IMPL_MAX_PROPRIETARY_CMD_SIZE),STRUCT_PROPRIETARY_CMD_TEMPLATE_IDX,
  };
  public static final short[] DATA_DISPATCH_RESP = {
      TAG_PROPRIETARY_RESP_TEMPLATE, (short)(MANDATORY|MAX| IMPL_MAX_PROPRIETARY_RESP_SIZE),
                                     STRUCT_PROPRIETARY_DISPATCH_RESP_IDX,
  };
  public static final short[] STRUCT_PROPRIETARY_DISPATCH_RESP = {
      TAG_PROPRIETARY_RESP_STATUS, (short) (MANDATORY | 1), ENUM_PROPRIETARY_DISPATCH_RESP_STATUS_IDX,
      TAG_PROPRIETARY_RESP_DATA, (short) (OPTIONAL | MAX | IMPL_MAX_PROPRIETARY_RESP_SIZE), NO_IDX,
      TAG_PROPRIETARY_RESP_NOTIFICATION,
              (short) (OPTIONAL | MAX | (short) (IMPL_MAX_PROPRIETARY_RESP_NOTIFICATION_SIZE + 4)),
              STRUCT_PROPRIETARY_RESP_NOTIFICATION_IDX,
  };
  public static final byte VAL_PROPRIETARY_RESP_NOTIFICATION_FMT = (short)0;
  public static final short[] STRUCT_PROPRIETARY_RESP_NOTIFICATION ={
      TAG_PROPRIETARY_RESP_NOTIFICATION_FMT, (short)(MANDATORY | 1),NO_IDX,
      TAG_PROPRIETARY_RESP_NOTIFICATION_ID, (short)(MANDATORY | 1),
                                             ENUM_PROPRIETARY_RESP_NOTIFICATION_ID_IDX,
      TAG_PROPRIETARY_RESP_NOTIFICATION_DATA,
              (short)(OPTIONAL | MAX | IMPL_MAX_PROPRIETARY_RESP_NOTIFICATION_SIZE), NO_IDX,
  };
  public static final short VAL_PROPRIETARY_RESP_NOTIFICATION_ID_OID = (short)0x00;
  public static final short VAL_PROPRIETARY_RESP_NOTIFICATION_ID_NONE =(short) 0x01;
  public static final short VAL_PROPRIETARY_RESP_NOTIFICATION_ID_RDS =(short) 0x02;
  public static final short[] ENUM_PROPRIETARY_RESP_NOTIFICATION_ID ={
      VAL_PROPRIETARY_RESP_NOTIFICATION_ID_OID,
      VAL_PROPRIETARY_RESP_NOTIFICATION_ID_NONE,
      VAL_PROPRIETARY_RESP_NOTIFICATION_ID_RDS,
  };
  public static final short VAL_PROP_DISPATCH_RESP_STATUS_TRANS_SUCCESS =(short) 0;
  public static final short VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER =(short) 0x80;
  public static final short VAL_PROP_DISPATCH_RESP_STATUS_RET_HOST =(short) 0x81;
  public static final short VAL_PROP_DISPATCH_RESP_STATUS_TRANS_ERROR =(short) 0xFF;
  public static final short[] ENUM_PROPRIETARY_DISPATCH_RESP_STATUS = {
      VAL_PROP_DISPATCH_RESP_STATUS_TRANS_SUCCESS,
      VAL_PROP_DISPATCH_RESP_STATUS_RET_PEER,
      VAL_PROP_DISPATCH_RESP_STATUS_RET_HOST,
      VAL_PROP_DISPATCH_RESP_STATUS_TRANS_ERROR,
  };

  // Tags
  // Instruction Payloads
  public static final short TAG_TERMINATE_SESSION = (short)0xBF79;
  public static final short TAG_PA_LIST =(short) 0xB0;
  public static final short TAG_STATIC_STS_SLOT_OID = (short)0xB1;
  public static final short TAG_APPLET_CERT_STORE = (short)0xBF21;
  public static final short TAG_DGI_ADD_PA_LIST =(short) 0x1000;
  public static final short TAG_DGI_ERASE_PA_LIST =(short) 0x1001;
  public static final short TAG_DGI_ERASE_ADF =(short) 0x2000;
  public static final short TAG_PA_ID =(short) 0xE1;
  public static final short TAG_CERT =(short) 0x7F21;

  // GET CMD
  public static final short TAG_GET_CMD = (short)0x4D;
/* //TODO Currently not used but if in future responses needs to be parsed then these structures
   // can be used
  public static final short[] DATA_GET_DATA_PA_LIST_RESP = {
      TAG_PA_ID,(short)( MANDATORY | MAX | 16), NO_IDX,
  };
  public static final short[] DATA_GET_DATA_CERTS_RESP = {
      TAG_CERT, (short)(MANDATORY | MAX | IMPL_MAX_FIRA_CERT_SIZE), NO_IDX, // Note: we do not parse the cert while responding
  };
  public static final short[] DATA_GET_DATA_STATIC_STS_RESP = {
      TAG_STATIC_STS_SLOT_OID,(short)(MANDATORY | MAX | IMPL_MAX_OID_SIZE), NO_IDX,
  };
*/
  // Store Data - uses DGI format.
  // Note: Main differences between BER-TLV and DGI TLV format is that tags is DGI are always 2 bytes
  // and length is either 1 byte of 3 bytes (first byte is oxFF). In BER TLV, Tags can very from
  // 1 to n bytes and the length is encoded differently. Also in BER TLV the 0 and 0xFF is not used
  // as Tags and they can occur between two BER TLV DOs.
  // TODO need to verify whether STORE DATA needs to be implemented by the applet or we need to use
  //  some personalization interface from GP.
  public static final short[] DATA_STORE_DATA = {
      TAG_DGI_ADD_PA_LIST, OPTIONAL, NO_IDX,
      TAG_DGI_ERASE_PA_LIST, OPTIONAL,NO_IDX,
      TAG_DGI_ERASE_ADF, OPTIONAL,NO_IDX,
  };

  // Sizes
  public static final short HEAP_SIZE =(short) 2000;

  //Response Status
  public static final short OID_NOT_FOUND =(short) 0x6200;
  public static final short OID_ALREADY_PRESENT =(short) 0x6400;
  public static final short WRONG_LENGTH = ISO7816.SW_WRONG_LENGTH;
  public static final short COND_NOT_SATISFIED = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
  public static final short WRONG_DATA = ISO7816.SW_WRONG_DATA;
  public static final short SEC_StATUS_NOT_SATISFIED = ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
  public static final short INCORRECT_P1P2 = ISO7816.SW_INCORRECT_P1P2;
  public static final short NO_ERROR = ISO7816.SW_NO_ERROR;
  public static final short REF_NOT_FOUND =(short) 0x6A88;
  public static final short SLOT_NOT_FOUND =(short) 0x6A82;

  // Session Data
  // Config parameters
  public static final short TAG_UWB_CONFIG_PARAMS =(short) 0xA3;
  public static final short TAG_CP_FIRA_PHY_VERSION =(short) 0x80;
  public static final short TAG_CP_FIRA_MAC_VERSION =(short) 0x81;
  public static final short TAG_CP_DEVICE_ROLE =(short) 0x80;

  public static final short VAL_CP_DEVICE_ROLE_RESPONDER =(short) 0;
  public static final short VAL_CP_DEVICE_ROLE_INITIATOR =(short) 1;
  public static final short[] ENUM_CP_DEVICE_ROLE = {
      VAL_CP_DEVICE_ROLE_RESPONDER,
      VAL_CP_DEVICE_ROLE_INITIATOR,
  };
  public static final short VAL_CP_RM_ONE_WAY =(short)0;
  public static final short VAL_CP_RM_SS_TWR_DEF_MODE =(short) 1;
  public static final short VAL_CP_RM_DS_TWR_DEF_MODE =(short) 2;
  public static final short VAL_CP_RM_SS_TWR_NON_DEF_MODE =(short) 3;
  public static final short VAL_CP_RM_DS_TWR_NON_DEF_MODE =(short) 4;
  public static final short[] ENUM_CP_RANGING_METHOD = {
    VAL_CP_RM_ONE_WAY,
    VAL_CP_RM_SS_TWR_DEF_MODE,
    VAL_CP_RM_DS_TWR_DEF_MODE,
    VAL_CP_RM_SS_TWR_NON_DEF_MODE,
    VAL_CP_RM_DS_TWR_NON_DEF_MODE,
  };
  public static final short VAL_CP_SC_STATIC_STS =(short) 0;
  public static final short VAL_CP_SC_DYNAMIC_STS =(short) 1;
  public static final short VAL_CP_SC_DYNAMIC_STS_WITH_RESPONDER =(short) 2;
  public static final short[] ENUM_CP_STS_CONFIG = {
      VAL_CP_SC_STATIC_STS,
      VAL_CP_SC_DYNAMIC_STS,
      VAL_CP_SC_DYNAMIC_STS_WITH_RESPONDER,
  };

  public static final short VAL_CP_ONE_TO_ONE =(short) 0;
  public static final short VAL_CP_ONE_TO_MANY =(short) 1;
  public static final short VAL_CP_MANY_TO_MANY =(short) 2;
  public static final short[] ENUM_CP_MULTI_NODE_MODE = {
      VAL_CP_ONE_TO_ONE,
      VAL_CP_ONE_TO_MANY,
      VAL_CP_MANY_TO_MANY,
  };

  public static final short VAL_CP_RT_INTERVAL =(short) 0;
  public static final short VAL_CP_RT_BLOCK =(short) 1;
  public static final short[] ENUM_CP_RANGING_TIME_STRUCT = {
      VAL_CP_RT_INTERVAL,
      VAL_CP_RT_BLOCK,
  };
  public static final short VAL_CP_CONTENTION_BASED_RANGING =(short)0;
  public static final short VAL_CP_TIME_SC_RANGING =(short)1;
  public static final short[] ENUM_CP_SCHEDULED_MODE = {
      VAL_CP_CONTENTION_BASED_RANGING,
      VAL_CP_TIME_SC_RANGING,
  };

  public static final short VAL_CP_HM_DISABLE =(short) 0;
  public static final short VAL_CP_HM_ENABLE =(short) 1;
  public static final short[] ENUM_CP_HOPPING_MODE = {
      VAL_CP_HM_DISABLE,
      VAL_CP_HM_ENABLE,
  };
  public static final short VAL_CP_BS_NO_BLOCK_STRIDING =(short) 0;
  public static final short VAL_CP_BS_SKIP_BLOCKS =(short) 1;
  public static final short[] ENUM_CP_BLOCK_STRIDING = {
      VAL_CP_BS_NO_BLOCK_STRIDING,
      VAL_CP_BS_SKIP_BLOCKS,
  };

  public static final short[] ENUM_CP_CHANNEL_NUMBER = {
      (short)5,(short)6,(short)8,(short)9,(short)10,(short)12,(short)13,(short)14,
  };

  public static final short VAL_CP_RF_SP0 =(short) 0;
  public static final short VAL_CP_RF_SP1 =(short) 1;
  public static final short VAL_CP_RF_SP2 =(short) 2;
  public static final short VAL_CP_RF_SP3 =(short) 3;
  public static final short[] ENUM_CP_RFRAME_CONFIG = {
      VAL_CP_RF_SP0,
      VAL_CP_RF_SP1,
      VAL_CP_RF_SP2,
      VAL_CP_RF_SP3,
  };

  public static final short VAL_CP_K_3 =(short) 0;
  public static final short VAL_CP_K_7 =(short) 1;
  public static final short[] ENUM_CP_CC_CONSTRAINT_LENGTH = {
      VAL_CP_K_3,
      VAL_CP_K_7,
  };

  public static final short VAL_CP_BPRF =(short) 0;
  public static final short VAL_CP_HPRF =(short) 1;
  public static final short[] ENUM_CP_PRF_MODE = {
      VAL_CP_BPRF,
      VAL_CP_HPRF,
  };

  public static final short[] ENUM_CP_PREAMBLE_CODE_INDEX = {
      (short)9,(short)10,(short)11,(short)12, // BPRF
      (short)25,(short)26,(short)27,(short)28,(short)29,(short)30,(short)31,(short)32, // HPRF
  };

  public static final short VAL_CP_MAC_ADDRESS_2_2 =(short) 0;
  public static final short VAL_CP_MAC_ADDRESS_8_2 =(short) 1;
  public static final short VAL_CP_MAC_ADDRESS_8_8 =(short) 2;
  public static final short[] ENUM_CP_MAC_ADDRESS_MODE = {
      VAL_CP_MAC_ADDRESS_2_2,
      VAL_CP_MAC_ADDRESS_8_2,
      VAL_CP_MAC_ADDRESS_8_8,
  };

  public static final short[] ENUM_CP_KEY_ROTATION_RATE = {
      (short)0,(short)1,(short)2,(short)3,(short)4,(short)5,(short)6,(short)7,(short)8,
      (short)9,(short)10,(short)11,(short)12,(short)13,(short)14,(short)15,
  };

  public static final short VAL_CP_FT_CRC_16 =(short) 0;
  public static final short VAL_CP_FT_CRC_32 =(short) 1;
  public static final short[] ENUM_CP_MAC_FCS_TYPE = {
      VAL_CP_FT_CRC_16,
      VAL_CP_FT_CRC_32,
  };


  public static final short VAL_CONFIG_AVAILABLE =(short) 1;
  public static final short VAL_CONFIG_NOT_AVAILABLE =(short) 0;
  public static final short[] ENUM_UWB_CONFIG_AVAILABLE = {
      VAL_CONFIG_NOT_AVAILABLE,
      VAL_CONFIG_AVAILABLE,
  };

  public static final short TAG_CP_RANGING_METHOD =(short) 0x83;
  public static final short TAG_CP_STS_CONFIG =(short) 0x84;
  public static final short TAG_CP_MULTI_NODE_MODE =(short) 0x85;
  public static final short TAG_CP_RANGING_TIME_STRUCT =(short) 0x86;
  public static final short TAG_CP_SCHEDULED_MODE  =(short) 0x87;
  public static final short TAG_CP_HOPPING_MODE  =(short) 0x88;
  public static final short TAG_CP_BLOCK_STRIDING  =(short) 0x89;
  public static final short TAG_CP_UWB_INITIATION_TIME  =(short) 0x8A;
  public static final short TAG_CP_CHANNEL_NUMBER  =(short) 0x8B;
  public static final short TAG_CP_RFRAME_CONFIG  =(short) 0x8C;
  public static final short TAG_CP_CC_CONSTRAINT_LENGTH =(short) 0x8D;
  public static final short TAG_CP_PRF_MODE =(short) 0x8E;
  public static final short TAG_CP_SP0_PHY_SET =(short) 0x8F;
  public static final short TAG_CP_SP1_PHY_SET =(short) 0x90;
  public static final short TAG_CP_SP3_PHY_SET =(short) 0x91;
  public static final short TAG_CP_PREAMBLE_CODE_INDEX =(short) 0x92;
  public static final short TAG_CP_RESULT_REPORT_CONFIG =(short) 0x93;
  public static final short TAG_CP_MAC_ADDRESS_MODE =(short) 0x94;
  public static final short TAG_CP_CONTROLEE_SHORT_MAC_ADDRESS =(short) 0x95;
  public static final short TAG_CP_CONTROLLER_MAC_ADDRESS =(short) 0x96;
  public static final short TAG_CP_SLOTS_PER_RR =(short) 0x97;
  public static final short TAG_CP_MAX_CONTENTION_PHASE_LENGTH =(short) 0x98;
  public static final short TAG_CP_SLOT_DURATION =(short) 0x99;
  public static final short TAG_CP_RANGING_INTERVAL =(short) 0x9A;
  public static final short TAG_CP_KEY_ROTATION_RATE =(short) 0x9B;
  public static final short TAG_CP_MAC_FCS_TYPE =(short) 0x9C;
  public static final short TAG_CP_MAX_RR_RETRY =(short) 0x9D;

  public static final short[] STRUCT_UWB_CONFIG_PARAMS = { // All params are kept optional
      TAG_CP_FIRA_PHY_VERSION, (short)(MANDATORY | 2) , NO_IDX ,
      TAG_CP_FIRA_MAC_VERSION, (short)(MANDATORY | 2), NO_IDX ,
      TAG_CP_DEVICE_ROLE, (short)(OPTIONAL | 1), ENUM_CP_DEVICE_ROLE_IDX,
      TAG_CP_RANGING_METHOD, (short)(OPTIONAL | 1), ENUM_CP_RANGING_METHOD_IDX,
      TAG_CP_STS_CONFIG, (short)(OPTIONAL | 1), ENUM_CP_STS_CONFIG_IDX,
      TAG_CP_MULTI_NODE_MODE,(short)(OPTIONAL | 1), ENUM_CP_MULTI_NODE_MODE_IDX,
      TAG_CP_RANGING_TIME_STRUCT, (short)(OPTIONAL | 1), ENUM_CP_RANGING_TIME_STRUCT_IDX,
      TAG_CP_SCHEDULED_MODE, (short)(OPTIONAL | 1), ENUM_CP_SCHEDULED_MODE_IDX,
      TAG_CP_HOPPING_MODE, (short)(OPTIONAL | 1), ENUM_CP_HOPPING_MODE_IDX,
      TAG_CP_BLOCK_STRIDING, (short)(OPTIONAL | 1), ENUM_CP_BLOCK_STRIDING_IDX,
      TAG_CP_UWB_INITIATION_TIME, (short)(OPTIONAL | 4), NO_IDX,
      TAG_CP_CHANNEL_NUMBER, (short)(OPTIONAL | 1), ENUM_CP_CHANNEL_NUMBER_IDX ,
      TAG_CP_RFRAME_CONFIG, (short)(OPTIONAL | 1), ENUM_CP_RFRAME_CONFIG_IDX ,
      TAG_CP_CC_CONSTRAINT_LENGTH, (short)(OPTIONAL | 1), ENUM_CP_CC_CONSTRAINT_LENGTH_IDX ,
      TAG_CP_PRF_MODE, (short)(OPTIONAL | 1), ENUM_CP_PRF_MODE_IDX,
      TAG_CP_SP0_PHY_SET, (short)(OPTIONAL | 1), NO_IDX,
      TAG_CP_SP1_PHY_SET, (short)(OPTIONAL | 1), NO_IDX,
      TAG_CP_SP3_PHY_SET, (short)(OPTIONAL | 1), NO_IDX,
      TAG_CP_PREAMBLE_CODE_INDEX, (short)(OPTIONAL | 1),ENUM_CP_PREAMBLE_CODE_INDEX_IDX,
      TAG_CP_RESULT_REPORT_CONFIG, (short)(OPTIONAL | 1), NO_IDX,
      TAG_CP_MAC_ADDRESS_MODE, (short)(OPTIONAL | 1), ENUM_CP_MAC_ADDRESS_MODE_IDX ,
      TAG_CP_CONTROLEE_SHORT_MAC_ADDRESS, (short)(OPTIONAL | 2), NO_IDX ,
      TAG_CP_CONTROLLER_MAC_ADDRESS, (short)(OPTIONAL | MAX |8), NO_IDX ,
      TAG_CP_SLOTS_PER_RR, (short)(OPTIONAL | 1), NO_IDX ,
      TAG_CP_MAX_CONTENTION_PHASE_LENGTH, (short)(OPTIONAL | 1), NO_IDX ,
      TAG_CP_SLOT_DURATION, (short)(OPTIONAL | 2), NO_IDX ,
      TAG_CP_RANGING_INTERVAL, (short)(OPTIONAL | 2), NO_IDX ,
      TAG_CP_KEY_ROTATION_RATE, (short)(OPTIONAL | 1), ENUM_CP_KEY_ROTATION_RATE_IDX ,
      TAG_CP_MAC_FCS_TYPE, (short)(OPTIONAL | 1), ENUM_CP_MAC_FCS_TYPE_IDX ,
      TAG_CP_MAX_RR_RETRY, (short)(OPTIONAL | 2), NO_IDX,
  };

  public static final short TAG_UWB_SESSION_DATA_VERSION = (short)0x80;
  public static final short TAG_UWB_SESSION_ID = (short)0x81;
  public static final short TAG_UWB_SUB_SESSION_ID = (short)0x82;
  public static final short TAG_UWB_CONFIG_AVAILABLE = (short)0x87;

  public static final short[] STRUCT_UWB_SESSION_DATA = {
      TAG_UWB_SESSION_DATA_VERSION, (short)(MANDATORY|2), NO_IDX,
      TAG_UWB_SESSION_ID, (short)(MANDATORY|4), NO_IDX,
      TAG_UWB_SUB_SESSION_ID,(short)(MANDATORY|4), NO_IDX,
      TAG_UWB_CONFIG_PARAMS, OPTIONAL, STRUCT_UWB_CONFIG_PARAMS_IDX,
      TAG_UWB_STATIC_RANGING_INFO, OPTIONAL, STRUCT_UWB_STATIC_RANGING_INFO_IDX,
      TAG_UWB_SECURE_RANGING_INFO, OPTIONAL, STRUCT_UWB_SECURE_RANGING_INFO_IDX,
      TAG_UWB_REGULATORY_INFO, OPTIONAL, STRUCT_UWB_REGULATORY_INFO_IDX,
      TAG_UWB_CONFIG_AVAILABLE, (short)(OPTIONAL | 1),ENUM_UWB_CONFIG_AVAILABLE_IDX,
  };

  public static final short IMPL_MAX_PERSISTENT_ADF_SLOTS = (short)2;
  public static final short IMPL_MAX_APPLET_ID_SIZE = (short)16; // 5 bytes of RID and 11 bytes of PIX
  public static final short IMPL_PERSISTENT_ADF_SIZE = (short)1000;
  public static final short IMPL_TRANSIENT_ADF_SIZE = (short)500;
  public static final short IMPL_MAX_TRANSIENT_ADF_SLOTS = (short)2;
  public static final short[] DATA_LOCAL_PUT_DATA = {
    TAG_UWB_CONTROLEE_INFO, (short)(OPTIONAL | MAX | IMPL_MAX_UWB_CONTROLEE_INFO_SIZE), STRUCT_UWB_CONTROLEE_INFO_IDX,
  };
  public static final short[] DATA_REMOTE_PUT_DATA = {
      TAG_TERMINATE_SESSION, (short)(OPTIONAL | 0), NO_IDX,
      TAG_UWB_CONTROLEE_INFO, (short) (OPTIONAL | MAX | IMPL_MAX_UWB_CONTROLEE_INFO_SIZE), STRUCT_UWB_CONTROLEE_INFO_IDX,
      TAG_UWB_SESSION_DATA,  (short) (OPTIONAL | MAX | IMPL_MAX_UWB_SESSION_DATA_SIZE), STRUCT_UWB_SESSION_DATA_IDX,
  };
  public static final short[] DATA_PA_RECORD = {
      TAG_PA_CRED_PA_ID, (short)(MANDATORY | MAX |30), NO_IDX,
      TAG_PA_CRED_PA_CRED_TYPE, (short)(MANDATORY |1), ENUM_PA_CRED_TYPE_IDX,
      TAG_PA_CRED_PA_CREDS, (short) (MANDATORY | MAX | 65), NO_IDX,
  };

  public static final short[] ENUM_PA_CRED_TYPE ={
      VAL_ECC_NIST_P_256,
  };

  public static final byte IMPL_MAX_SERVICE_APPLETS = (byte)4;

  public static final short[] expressionTable (byte index) {
    switch(index){
      case STRUCT_ADF_PROVISIONING_CRED_IDX:
        return STRUCT_ADF_PROVISIONING_CRED;
      case STRUCT_FIRA_SC_SYMMETRIC_KEY_SET_IDX:
        return STRUCT_FIRA_SC_SYMMETRIC_KEY_SET;
      case STRUCT_FIRA_SC_ASYMMETRIC_KEY_SET_IDX:
        return STRUCT_FIRA_SC_ASYMMETRIC_KEY_SET;
      case STRUCT_UWB_CONTROLEE_INFO_IDX:
        return STRUCT_UWB_CONTROLEE_INFO;
      case STRUCT_UWB_CAPABILITY_IDX:
        return STRUCT_UWB_CAPABILITY;
      case STRUCT_UWB_CONTROLEE_PREF_IDX:
        return STRUCT_UWB_CONTROLEE_PREF; //5
      case STRUCT_UWB_STATIC_RANGING_INFO_IDX:
        return STRUCT_UWB_STATIC_RANGING_INFO;
      case STRUCT_UWB_SECURE_RANGING_INFO_IDX:
        return STRUCT_UWB_SECURE_RANGING_INFO;
      case STRUCT_UWB_REGULATORY_INFO_IDX:
        return STRUCT_UWB_REGULATORY_INFO;
      case STRUCT_UWB_CONFIG_PARAMS_IDX:
        return STRUCT_UWB_CONFIG_PARAMS;
      case STRUCT_UWB_SESSION_DATA_IDX:
        return STRUCT_UWB_SESSION_DATA; //10
      case STRUCT_FIRA_SC_CRED_IDX:
        return STRUCT_FIRA_SC_CRED;
      case STRUCT_FIRA_SC_SYMMETRIC_BASE_KEY_IDX:
        return STRUCT_FIRA_SC_SYMMETRIC_BASE_KEY;
      case STRUCT_FIRA_SC_UWB_RANGING_ROOT_KEY_IDX:
        return STRUCT_FIRA_SC_UWB_RANGING_ROOT_KEY;
      case STRUCT_ADF_PROV_SYMMETRIC_KEY_SET_IDX:
        return STRUCT_ADF_PROV_SYMMETRIC_KEY_SET;
      case STRUCT_ADF_PROV_ASYMMETRIC_KEY_SET_IDX:
        return STRUCT_ADF_PROV_ASYMMETRIC_KEY_SET; //15
      case STRUCT_SWAP_ADF_SECURE_BLOB_IDX:
        return STRUCT_SWAP_ADF_SECURE_BLOB;
      case STRUCT_PROPRIETARY_CMD_TEMPLATE_IDX:
        return STRUCT_PROPRIETARY_CMD_TEMPLATE;
      case STRUCT_PROPRIETARY_TUNNEL_RESP_TEMPLATE_IDX:
        return STRUCT_PROPRIETARY_TUNNEL_RESP_TEMPLATE;
      case STRUCT_PROPRIETARY_DISPATCH_RESP_IDX:
        return STRUCT_PROPRIETARY_DISPATCH_RESP;
      case STRUCT_PROPRIETARY_RESP_NOTIFICATION_IDX:
        return STRUCT_PROPRIETARY_RESP_NOTIFICATION; //20
      case STRUCT_SWAP_ADF_STATIC_STS_IDX:
        return STRUCT_SWAP_ADF_STATIC_STS;
      case STRUCT_CMD_ROUTE_INFO_IDX:
        return STRUCT_CMD_ROUTE_INFO;
      case STRUCT_CMD_ROUTING_DATA_IDX:
        return STRUCT_CMD_ROUTING_DATA; //,null, //24
      case ENUM_FIRA_SC_KEY_TYPE_IDX:
        return ENUM_FIRA_SC_KEY_TYPE; //0
      case ENUM_ADF_PROV_CH_KEY_TYPE_IDX:
        return ENUM_ADF_PROV_CH_KEY_TYPE;
      case ENUM_CP_DEVICE_ROLE_IDX:
        return ENUM_CP_DEVICE_ROLE;
      case ENUM_CP_RANGING_METHOD_IDX:
        return ENUM_CP_RANGING_METHOD;
      case ENUM_CP_STS_CONFIG_IDX:
        return ENUM_CP_STS_CONFIG;
      case ENUM_CP_MULTI_NODE_MODE_IDX:
        return ENUM_CP_MULTI_NODE_MODE; // 5
      case ENUM_CP_RANGING_TIME_STRUCT_IDX:
        return ENUM_CP_RANGING_TIME_STRUCT;
      case ENUM_CP_SCHEDULED_MODE_IDX:
        return ENUM_CP_SCHEDULED_MODE;
      case ENUM_CP_HOPPING_MODE_IDX:
        return ENUM_CP_HOPPING_MODE;
      case ENUM_CP_BLOCK_STRIDING_IDX:
        return ENUM_CP_BLOCK_STRIDING;
      case ENUM_CP_CHANNEL_NUMBER_IDX:
        return ENUM_CP_CHANNEL_NUMBER; //10
      case ENUM_CP_RFRAME_CONFIG_IDX:
        return ENUM_CP_RFRAME_CONFIG;
      case ENUM_CP_CC_CONSTRAINT_LENGTH_IDX:
        return ENUM_CP_CC_CONSTRAINT_LENGTH;
      case ENUM_CP_PRF_MODE_IDX:
        return ENUM_CP_PRF_MODE;
      case ENUM_CP_PREAMBLE_CODE_INDEX_IDX:
        return ENUM_CP_PREAMBLE_CODE_INDEX;
      case ENUM_CP_MAC_ADDRESS_MODE_IDX:
        return ENUM_CP_MAC_ADDRESS_MODE; //15
      case ENUM_CP_KEY_ROTATION_RATE_IDX:
        return ENUM_CP_KEY_ROTATION_RATE;
      case ENUM_CP_MAC_FCS_TYPE_IDX:
        return ENUM_CP_MAC_FCS_TYPE;
      case ENUM_UWB_CONFIG_AVAILABLE_IDX:
        return ENUM_UWB_CONFIG_AVAILABLE;
      case ENUM_FIRA_SC_SYMMETRIC_BASE_KEY_CH_ID_IDX:
        return ENUM_FIRA_SC_SYMMETRIC_BASE_KEY_CH_ID;
      case ENUM_FIRA_SC_KEY_USAGE_IDX:
        return ENUM_FIRA_SC_KEY_USAGE; //20
      case ENUM_ADF_PROV_SYMMETRIC_CH_ID_IDX:
        return ENUM_ADF_PROV_SYMMETRIC_CH_ID;
      case ENUM_ADF_PROV_ASYMMETRIC_CH_ID_IDX:
        return ENUM_ADF_PROV_ASYMMETRIC_CH_ID;
      case ENUM_FIRA_SC_SYMMETRIC_CH_ID_IDX:
        return ENUM_FIRA_SC_SYMMETRIC_CH_ID;
      case ENUM_FIRA_SC_ASYMMETRIC_CH_ID_IDX:
        return ENUM_FIRA_SC_ASYMMETRIC_CH_ID;
      case ENUM_PROPRIETARY_DISPATCH_RESP_STATUS_IDX:
        return ENUM_PROPRIETARY_DISPATCH_RESP_STATUS; //25
      case ENUM_PROPRIETARY_RESP_NOTIFICATION_ID_IDX:
        return ENUM_PROPRIETARY_RESP_NOTIFICATION_ID;
      case ENUM_CMD_ROUTING_TARGET_IDX:
        return ENUM_CMD_ROUTING_TARGET;
      case ENUM_PA_CRED_TYPE_IDX:
        return ENUM_PA_CRED_TYPE;
  }
    return null;
  }
}
