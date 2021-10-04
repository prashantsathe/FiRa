package com.android.fira.applet;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;

import static javacard.framework.ISO7816.OFFSET_P1;

@SuppressWarnings("FieldCanBeLocal")
public class FiraApplet extends Applet implements ExtendedLength {

    private static final short KM_HAL_VERSION = (short) 0x4000;
    private static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;

    protected static byte[] mHeapBuffer;
    protected static short m_ExtBufLength;

    private static ADFManager mAdfManager;
    private static SessionManager mSessionManager;
    private static Repository mRepository;


    /**
     * Registers this applet.
     */
    protected FiraApplet() {
        mAdfManager = new ADFManager();
        mSessionManager = new SessionManager();
        mRepository = new Repository();
        mHeapBuffer = JCSystem.makeTransientByteArray(Constant.HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FiraApplet().register();
    }

    @Override
    public void deselect() {
    }

    /**
     * brief This method is called whenever the applet is being selected.
     */
    @Override
    public boolean select() {
        return true;
    }

    protected void validateApduHeader(APDU apdu) {
        // Read the apdu header and buffer.
        byte[] apduBuffer = apdu.getBuffer();
        byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];
        short P1P2 = Util.getShort(apduBuffer, OFFSET_P1);

        // Validate APDU Header.
        if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Validate P1P2.
        if (P1P2 != FiraApplet.KM_HAL_VERSION) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Receive extended data
     */
    public static void receiveIncoming(APDU apdu) {
        byte[] srcBuffer = apdu.getBuffer();
        short revLen = apdu.setIncomingAndReceive();
        short srcOffset = apdu.getOffsetCdata();
        m_ExtBufLength = apdu.getIncomingLength();
        short index = 0;

        while (revLen > 0 && index  < m_ExtBufLength) {
            Util.arrayCopyNonAtomic(srcBuffer, srcOffset, mHeapBuffer, index, revLen);
            index += revLen;
            revLen = apdu.receiveBytes(srcOffset);
        }
    }

    private void processSwapADF(APDU apdu) {
        boolean acquire = apdu.getBuffer()[ISO7816.OFFSET_P1] == 0x00;
        byte[] adfBuff = mRepository.getADFBuffers();
        short adfFreeIndex = mRepository.getFreeIndex();

        if (adfFreeIndex == -1) {
            /* Error set */
            return;
        }

        short adfFreeIndexOffset = mRepository.getFreeIndexOffset(adfFreeIndex);

        receiveIncoming(apdu);

        if(acquire) {
            if (!mAdfManager.parserAndValidateSwapAdf(adfBuff, adfFreeIndexOffset, Constant.ADF_SIZE,
                    mHeapBuffer, (short) 0, m_ExtBufLength)) {
                /*TODO:- */
                return;
            }
            mRepository.setADF(adfFreeIndex);

        } else {

        }

        /* TODO:- return response */
    }

    private void processSelectADF(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short revLen = apdu.setIncomingAndReceive();
        short srcOffset = apdu.getOffsetCdata();
        short dataLen = apdu.getIncomingLength();

        /*TODO:- return response*/
    }

    private void processSelect(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short revLen = apdu.setIncomingAndReceive();
        short srcOffset = apdu.getOffsetCdata();
        short dataLen = apdu.getIncomingLength();
        // check dataLen == revLen ??
        if (!mRepository.verifyAID(apduBuffer, srcOffset, dataLen)) {
            /*TODO:- return response*/
            return;
        }
    }

    @Override
    public void process(APDU apdu) {
        /* SELECT / Check swap CLA 0x80-83, 0xC0-CF */
        if (apdu.isISOInterindustryCLA()) {
            if (selectingApplet()) {
                return;
            }
        }

        validateApduHeader(apdu);
        byte apduIns = apdu.getBuffer()[ISO7816.OFFSET_INS];

        /* TODO: Exception catch */
        switch (apduIns) {
            case Constant.INS_SELECT:
                // processSelect(apdu);
            case Constant.INS_SELECT_ADF:
                //processSelectADF(apdu);
                break;
            case Constant.INS_SWAP_ADF:
                /* TODO: make sure to call this INS before any secure channel */
                processSwapADF(apdu);
                break;
        }
    }
}
