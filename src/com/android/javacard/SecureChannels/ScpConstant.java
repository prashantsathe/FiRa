package com.android.javacard.SecureChannels;

public class ScpConstant {

    /* INS */
    public static final byte PERFORM_SECURITY_OPERATION = 0x2A;
    public static final byte MUTUAL_AUTHENTICATE = (byte) 0x82;

    /* certificate constants (tags)*/
    public static final short TAG_CERTIFICATE = (short) 32545;
    public static final short TAG_CSN = (short) 147;
    public static final short TAG_KLOC_IDENTIFIER = (short) 66;
    public static final short TAG_SUBJECT_IDENTIFIER = (short) 24352;
    public static final short TAG_KEY_USAGE = (short) 149;
    public static final short TAG_EFFECTIVE_DATE = (short) 24357;
    public static final short TAG_EXPIRATION_DATE = (short) 24356;
    public static final short TAG_DISCRETIONARY_DATE = (short) 83;
    public static final short TAG_DISCRETIONARY_DATE2 = (short) 115;
    public static final short TAG_SCP11C_AUTHORIZATION = (short) -16608;
    public static final short TAG_PUBLIC_KEY = (short) 32585;
        public static final byte TAG_PUBLIC_KEY_Q = (byte) 0xB0;
        public static final byte TAG_KEY_PARAMETERS_REF = (byte) 0xF0;
    public static final short TAG_SIGNATURE = (short) 24375;

    /* CRT constants (tags)*/
    public static final short TAG_CRT = (short) 166;
    public static final byte TAG_SCP_IDENTIFIFER = (byte) 0x90;
    public static final byte TAG_KEY_USAGE_QUALIFIER = (byte) 0x95;
    public static final byte TAG_KEY_TYPE = (byte) 0x80;
    public static final byte TAG_KEY_LENGTH = (byte) 0x81;
    public static final byte TAG_HOSTID = (byte) 0x84;
    public static final short TAG_PK_OCE_ECKA = (short) 24393;

    /* ADF credential constants */
    public static final byte GP_SCP11C_KEYSET = (byte) 0x04;

    /* General Constants */
    public static final short HEAP_SIZE = 2048;
    public static final short LENGTH_BLOCK_AES  = (short) 16;
    public static final short NU_CERTIFICATE  = (short) 5;
    public static final short MAX_CERT_SIZE  = (short) 512;
    // max CSN size is 16+2 bytes, so keeping 60 CSN in memory TODO:(size TBD)
    public static final short MAX_CSN_COUNT  = (short) 18 * 10;
    public static final byte SCP11C = (byte) 0x00;
    public static final byte FREE = (byte) 0x00;

    /* SCP status */
    public static final byte START_DONE_STATE = (byte) 0x00; // DONE = MU
    public static final byte PSO_STATE = (byte) 0x01;

    /* Exceptions */
    // '6A' '80' Incorrect values in command data
    public static final short INCORRECT_VAL_IN_CMD = (short) 27264;
    // '6A' '88' Referenced PK.CA-KLOC.ECDSA not found
    //  One of the following referenced data elements is not found:
    //  SK.SD.ECKA / PK.OCE.ECKA / SIN / SDIN
    public static final short PK_KLOC_NOT_FOUND = (short) 27272;
    // '6A' '81' 'BF20' authorization mechanism not supported
    public static final short BF20_NOT_SUPPORTED = (short) 27265;
    // '66' '40' Certificate not in whitelist
    public static final short CERT_NOT_IN_WHITELIST = (short) 26176;
    // '66' '00' Verification of the certificate failed
    public static final short CERT_VERIFICATION_FAILED = (short) 26112;
    // '69' '85' Attempt to initiate an SCP11c session but one SCP11c
    // session is already ongoing on another logical channel .....
    public static final short ANOTHER_SCP11C_SESSION_IS_ACTIVE = (short) 27013;

    public static final byte AUTHENTICATED = (byte) 0x80;
    public static final byte C_DECRYPTION = (byte) 0x02;
    public static final byte C_MAC = (byte) 0x01;
    public static final byte R_ENCRYPTION = (byte) 0x20;
    public static final byte R_MAC = (byte) 0x10;
    public static final byte NO_SECURITY_LEVEL = (byte) 0x00;
    public static final byte ANY_AUTHENTICATED = (byte) 0x40;

    /* Authentication levels (mapped to Key Usage Qualifier) */
    // Table B-1: Authentication Levels in SCP11c
    // C-MAC = '14', R-MAC = '24', C-MAC + R-MAC = '34'
    // C-ENC = '18', R-ENC = '28', C-ENC + R-ENC = '38'
    // C-DEK = '48', R-DEK = '88', C-DEK + R-DEK = 'C8'
    // ANY_AUTHENTICATED | C_MAC | R_MAC
    public static final byte AUTH_CMAC_RMAC = (byte) 0x34;
    // ANY_AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION
    public static final byte AUTH_CMACDES_RMACENC = (byte) 0x3C;
    // ANY_AUTHENTICATED | C_MAC | C_DECRYPTION
    public static final byte AUTH_CMACDES = (byte) 0x1C;
    // ANY_AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC
    public static final byte AUTH_CMACDES_RMAC = (byte) 0x74;

    // FiRa security level (Table 43 - Security Level)
    // C-DEC, C-MAC, R-ENC, RMAC
    public static final byte CDECMAC_RENCMAC = (byte) 0x33;
    // C-DEC, C-MAC, R-MAC
    public static final byte CDECMAC_RMAC = (byte) 0x13;
    // C-MAC, R-MAC
    public static final byte CMAC_RMAC = (byte) 0x11;
    // C-DEC, C-MAC
    public static final byte CDECMAC = (byte) 0x03;
    // C-MAC
    public static final byte CMAC = (byte) 0x01;
}
