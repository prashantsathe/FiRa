package com.android.fira.applet;

import com.android.ber.BerArrayLinkList;
import com.android.ber.BerTlvParser;
import javacard.framework.*;


public class FiraApplet extends Applet {

    private static final short KM_HAL_VERSION = (short) 0x4000;
    private static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;
    private static final byte INS_SELECT_ADF = (byte) 165; //0xA5;

    /**
     * Registers this applet.
     */
    protected FiraApplet() {

//        seProvider = seImpl;
//        boolean isUpgrading = seImpl.isUpgrading();
//        repository = new KMRepository(isUpgrading);
//        initializeTransientArrays();
//        if (!isUpgrading) {
//            keymasterState = KMKeymasterApplet.INIT_STATE;
//            seProvider.createMasterKey((short) (KMRepository.MASTER_KEY_SIZE * 8));
//        }
//          KMType.initialize();
//        encoder = new KMEncoder();
//        decoder = new KMDecoder();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FiraApplet().register();
    }

    protected void validateApduHeader(APDU apdu) {
        // Read the apdu header and buffer.
        byte[] apduBuffer = apdu.getBuffer();
        byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];
        short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);

        // Validate APDU Header.
        if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Validate P1P2.
        if (P1P2 != FiraApplet.KM_HAL_VERSION) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }


    private void ProcessSelectADF(byte[] buffer, short offSet, short length) {
        BerTlvParser parser = new BerTlvParser();
        BerArrayLinkList berList = parser.Parser(buffer, offSet, length);

        berList.PrintAllTags(buffer);
        /*TODO:- return response*/
    }

    @Override
    public void process(APDU apdu) {

        /* NOTE: This is a test function to verify BER parser/builder */
        /* SELECT ins */
        if (apdu.isISOInterindustryCLA()) {
            if (selectingApplet()) {
                return;
            }
        }

        /* SELECT_ADF ins*/
        validateApduHeader(apdu);
        byte[] apduBuffer = apdu.getBuffer();
        byte apduIns = apduBuffer[ISO7816.OFFSET_INS];
        short dataLen = (short) apduBuffer[4];

        switch (apduIns) {
            case INS_SELECT_ADF:
                ProcessSelectADF(apduBuffer, (short) 5, dataLen);
            break;
        }
    }
}
