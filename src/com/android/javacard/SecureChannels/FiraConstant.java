package com.android.javacard.SecureChannels;

public class FiraConstant {
    public static final byte C_00 = (byte) 0x00;
    public static final byte C_04 = (byte) 0x04;
    public static final byte T_06 = (byte) 0x06;
    public static final byte T_2D = (byte) 0x2D;
    public static final byte T_2F = (byte) 0x2F;
    public static final byte T_4B = (byte) 0x4B;
    public static final byte T_6F = (byte) 0x6F;
    public static final byte T_70 = (byte) 0x70;
    public static final byte T_7C = (byte) 0x7C;
    public static final byte T_80 = (byte) 0x80;
    public static final byte T_81 = (byte) 0x81;
    public static final byte T_82 = (byte) 0x82;
    public static final byte T_83 = (byte) 0x83;
    public static final byte T_84 = (byte) 0x84;
    public static final byte T_85 = (byte) 0x85;
    public static final byte T_86 = (byte) 0x86;
    public static final byte T_8E = (byte) 0x8E;
    public static final byte T_B4 = (byte) 0xB4;
    public static final byte T_C0 = (byte) 0xC0;
    public static final byte T_CD = (byte) 0xCD;
    public static final byte T_CF = (byte) 0xCF;
    public static final byte T_E0 = (byte) 0xE0;
    public static final byte T_E1 = (byte) 0xE1;
    public static final byte FCI_6F = 0x6F;
    public static final byte FCI_81 = T_81;
    public static final byte FCI_84 = T_84;
    public static final byte FCI_85 = T_85;
    public static final byte FCI_86 = T_86;
    public static final byte RES_7C = T_7C;
    public static final byte RES_7F = 0x7F;
    public static final byte RES_82 = T_82;
    public static final byte RES_CD = T_CD;
    public static final short DEVICE_IDENTIFIER_SIZE = 13;
    public static final short MAX_OID_SIZE = 30;
    // Table 19 – Response SELECT_ADF – AlgorithmInfo field
    public static final byte AES128_CBC = 0x09;
    public static final byte AES256_CBC = 0x0D;

    public static final short IN_DATA_SIZE = 2048;
    public static final short OUT_DATA_SIZE = 256;

    // FiRa Secure Channel Credentials constants
    // 0x01: SC1
    // 0x81: SC1 privacy keyset
    // 0x02: SC2
    // 0x82: SC2 privacy keyset
    public static final short IN_DATA_KEYSET_OFFSET = IN_DATA_SIZE - 512;
    public static final short UWB_DATA_OFFSET = IN_DATA_KEYSET_OFFSET;
    public static final byte SC1_KEYSET = 0x01;
    public static final byte SC1_PRIVACY_KEYSET = (byte) 0x81;
    public static final byte SC2_KEYSET = 0x02;
    public static final byte SC2_PRIVACY_KEYSET = (byte) 0x82;
    public static final byte UWB_ROOT_KEYSET = (byte) 84;
    public static final byte MAC_KEYTYPE = (byte) 0x84;
    public static final byte ENC_KEYTYPE = (byte) 0x85;
    public static final byte CA_PUB_KEYTYPE = (byte) 0x84;
    public static final byte PUB_KEY_CERTIFICATE = (byte) 0x85;
    public static final byte PRIVATE_KEYTYPE = (byte) 0x86;
    public static final byte UWB_ROOT_KEYTYPE = (byte) 0x84;
    public static final byte SECURE_CHANNEL_IDENTIFIER = (byte) 0x80;
    public static final short BlOCK_16BYTES = (short) 16;
    public static final short LOWER_HIGHER_BYTE_SIZE = (short) 8;
    public static final short UWB_SESSION_ID_SIZE = (short) 4;
    public static final short SIGNATURE_BLOCK_SIZE = BlOCK_16BYTES;
    public static final short EC_SK_KEY_LENGTH = (short) (BlOCK_16BYTES * 2);
    public static final short EC_PK_KEY_LENGTH = (short) ((EC_SK_KEY_LENGTH * 2) + 1);
    public static final short ECD_64BYTES_SIGNATURE = (short) 64;
    public static final short ERROR = (short) -1;
    public static final short SUCCESS = (short) 0;
    public static final short NULL = (short) -1;
    public static final short TAG_KVN = 0x83;
    public static final byte TAG_SYMMETRIC_KEY_SET =(byte) 0xB9;
    public static final byte TAG_ASYMMETRIC_KEY_SET =(byte) 0xBA;

    // ADF extended options
    // UWB Session Key Derivation Scheme
    public static final byte E_DERIVE_FROM_SC_SESSION_KEY = (byte) 0x80;
    public static final byte E_USE_UWB_INFO = (byte) 0x80;
    public static final byte E_USE_UWB_SESSION_INFO_AS_DIVERSIFICATION_DATA = (byte) 0xE0;

    // SCP status
    public static final byte SC_SELECT_NO_CONNECTION = (byte) 0x00;
    public static final byte SC1_SELECT_ADF = (byte) 0x01;
    public static final byte SC2_SELECT_ADF_SYS = (byte) 0x02;
    public static final byte SC2_SELECT_ADF_ASYS = (byte) 0x03;
    public static final byte SC1_GA1 = (byte) 0x04;
    public static final byte SC2_GA1 = (byte) 0x05;
    public static final byte SC1_GA2 = (byte) 0x06;
    public static final byte SC2_GA2 = (byte) 0x07;
    public static final byte SC2_GA = (byte) 0x08;
    public static final byte CONNECTION_DONE = (byte) 0x09; // command success

    // Authentication method table 35
    public static final byte SYM = 0x00;
    public static final byte ASYM_UNILATERAL = 0x40;
    public static final byte ASYM_UNILATERAL_SEAMLESS = 0x48;
    public static final byte ASYM_MUTUAL = (byte) 0x80;
    public static final byte ASYM_MUTUAL_SEAMLESS = (byte) 0x88;
    public static final byte NONE = (byte) 0xFF;

    // Table 4-1: Data Derivation Constants SCP03_v1.1.2_PublicRelease
    // 0 0 0 0 0 1 0 0 - derivation of S-ENC
    // 0 0 0 0 0 1 1 0 - derivation of S-MAC
    // 0 0 0 0 0 1 1 1 - derivation of S-RMAC
    public static final byte DERIVATION_SENC = 0x04;
    public static final byte DERIVATION_SMAC = 0x06;
    public static final byte DERIVATION_RMAC = 0x07;
    public static final byte CONST_CRYPTOGRAM = 0x00;

    // Default UWB session key
    public static final byte DERIVATION_UWB_SESSION_KEY = 0x00;
    public static final byte DERIVATION_UWB_SESSION_ID = 0x01;

    // INS
    public static final byte INS_SELECT = (byte) 0xA4;
    public static final byte INS_SELECT_ADF = (byte) 0xA5;
    public static final byte INS_GA1_GA2 = (byte) 0x87;

    // FiRa context states
    public static final byte RESPONDER = (byte) 0x00;
    public static final byte INITIATOR = (byte) 0x01;
    public static final byte UNSECURE = (byte) 0x00;
    public static final byte SELECT_ADF = (byte) 0x01;
    public static final byte GENERAL_AUTH1 = (byte) 0x02;
    public static final byte GENERAL_AUTH2 = (byte) 0x03;
    public static final byte SECURE = (byte) 0x04;
    public static final byte INVALID_VALUE = (byte) -1;
}
