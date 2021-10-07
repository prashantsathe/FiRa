package com.android.fira.applet;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;
import javacard.framework.MultiSelectable;

import static javacard.framework.ISO7816.OFFSET_P1;

@SuppressWarnings("FieldCanBeLocal")
public class FiraApplet extends Applet implements ExtendedLength, MultiSelectable {

    private static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;

    private static byte[] mHeapBuffer;
    private static byte[] mSendOutBuffer;
    private static short mExtBufLength;

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
        mSendOutBuffer = JCSystem.makeTransientByteArray(Constant.SEND_BUFFER_SIZE, JCSystem.CLEAR_ON_RESET);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FiraApplet().register();
    }

    protected void validateApduHeader(APDU apdu) {
        // Read the apdu header and buffer.
        byte[] apduBuffer = apdu.getBuffer();
        byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];

        // Validate APDU Header.
        if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    /**
     * Receive extended data
     */
    public static void receiveIncoming(APDU apdu) {
        byte[] srcBuffer = apdu.getBuffer();
        short revLen = apdu.setIncomingAndReceive();
        short srcOffset = apdu.getOffsetCdata();
        mExtBufLength = apdu.getIncomingLength();
        short index = 0;

        while (revLen > 0 && index  < mExtBufLength) {
            Util.arrayCopyNonAtomic(srcBuffer, srcOffset, mHeapBuffer, index, revLen);
            index += revLen;
            revLen = apdu.receiveBytes(srcOffset);
        }
    }

    private void processSwapADF(APDU apdu) {

        if (apdu.getBuffer()[ISO7816.OFFSET_P2] != 0x00 || !(
                apdu.getBuffer()[ISO7816.OFFSET_P1] >= 0x00 &&
                        apdu.getBuffer()[ISO7816.OFFSET_P1] <= 0x01 )) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        boolean acquire = apdu.getBuffer()[ISO7816.OFFSET_P1] == (byte) 0x01;
        byte[] adfBuff = mRepository.getADFBuffers();
        short adfFreeIndex = mRepository.getFreeIndex();

        if (adfFreeIndex != -1) {
            short adfFreeIndexOffset = mRepository.getFreeIndexOffset(adfFreeIndex);

            receiveIncoming(apdu);

            /* TODO: check whether ADF is already present using OID
            *        And return ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED) if present
            */

            if(acquire) {
                if (!mAdfManager.parserAndValidateSwapAdf(adfBuff, adfFreeIndexOffset, Constant.ADF_SIZE,
                        mHeapBuffer, (short) 0, mExtBufLength)) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                } else {
                    mRepository.setADF(adfFreeIndex);
                }
            } else {
                mRepository.resetADF(adfFreeIndex);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }

        /* return response */
        sendOutgoing(apdu, setSuccessStatus(setReturnSlotID(adfFreeIndex)));
    }

    private void processImportADF(APDU apdu) {
        short encryptLen = 0;
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0x00 ||
                apdu.getBuffer()[ISO7816.OFFSET_P2] != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        receiveIncoming(apdu);

        /* TODO: Check ADF contents */

        if ((encryptLen = mAdfManager.encryptImportAdf(mHeapBuffer, (short) 0, mSendOutBuffer, (short) 0)) <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        /* return response */
        sendOutgoing(apdu, setSuccessStatus(encryptLen));
    }

    private void processSelectADF(APDU apdu) {
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0x00 || !(
                apdu.getBuffer()[ISO7816.OFFSET_P2] >= 0x00 &&
                        apdu.getBuffer()[ISO7816.OFFSET_P2] <= 0x1F )) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        receiveIncoming(apdu);

        /*TODO:- return response*/
    }


    private void processSelect(APDU apdu) {
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] != 0x04 ||
                apdu.getBuffer()[ISO7816.OFFSET_P2] != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        byte[] apduBuffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        short srcOffset = apdu.getOffsetCdata();

        if (!mRepository.verifyAID(apduBuffer, srcOffset, dataLen)) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        /* return response */
        sendOutgoing(apdu, setSuccessStatus((short) 0));
    }

    @Override
    public void process(APDU apdu) {

        try {
            /* TODO:- Check CLA standard, SELECT / Check swap CLA 0x80-83, 0xC0-CF */
            if (apdu.isISOInterindustryCLA()) {
                if (selectingApplet()) {
                    return;
                }
            }

            validateApduHeader(apdu);
            byte apduIns = apdu.getBuffer()[ISO7816.OFFSET_INS];

            /*TODO: need to move all p1p2 calculation outside */
            short P1P2 = Util.getShort(apdu.getBuffer(), OFFSET_P1);

            switch (apduIns) {
                case Constant.INS_SWAP_ADF:
                    /* Make sure to call this INS before any secure channel */
                    processSwapADF(apdu);
                    break;
                case Constant.INS_IMPORT_ADF:
                    processImportADF(apdu);
                    break;
                case Constant.INS_SELECT:
                    processSelect(apdu);
                case Constant.INS_SELECT_ADF:
                    //processSelectADF(apdu);
                    break;
            }
        } catch (ISOException exp) {
            sendError(apdu, exp.getReason());
        }
    }

    @Override
    public boolean select(boolean b) {
        return false;
    }

    @Override
    public void deselect(boolean b) {

    }

    private void sendError(APDU apdu, short err) {
        Util.setShort(mSendOutBuffer, (short) 0, err);
        sendOutgoing(apdu, (short)2);
    }

    private void sendOutgoing(APDU apdu, short length) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(mSendOutBuffer, (short) 0, length);
    }

    private short setReturnSlotID(short slotID) {
        Util.setShort(mSendOutBuffer, (short) 0, slotID);
        return (short) 2; // return offset of mSendOutBuffer
    }

    private short setSuccessStatus(short offSet) {
        Util.setShort(mSendOutBuffer, (short) offSet, ISO7816.SW_NO_ERROR);
        return (short) (offSet + 2); // return offset of mSendOutBuffer
    }
}
