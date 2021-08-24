package com.android.fira.applet;

import com.android.ber.BerTlv;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class FiraTest {

    private static final byte INS_SET_VERSION_PATCHLEVEL_CMD = 9;
    private static final byte INS_SELECT_ADF = (byte) 165; //0xA5;
    private static final int OS_VERSION = 1;
    private static final int OS_PATCH_LEVEL = 1;
    private static final int VENDOR_PATCH_LEVEL = 1;

    private CardSimulator simulator;

    public FiraTest() {
        //cryptoProvider = new KMJCardSimulator();
        simulator = new CardSimulator();
        //encoder = new KMEncoder();
        //decoder = new KMDecoder();
    }

    private void init() {
        // Create simulator
        AID appletAID = AIDUtil.create("A000000062");
        simulator.installApplet(appletAID, FiraApplet.class);

        // Select applet
        simulator.selectApplet(appletAID);

    }

    private CommandAPDU encodeApdu(byte ins, byte[] cmd, short cmdLen) {
        byte[] buf = new byte[2500];
        buf[0] = (byte) 0x80;
        buf[1] = ins;
        buf[2] = (byte) 0x40;
        buf[3] = (byte) 0x00;

        /* cmdLeng */
        buf[4] = 0x1A;

        Util.arrayCopyNonAtomic(cmd, (short) 0, buf, (short) 5, cmdLen);
        return new CommandAPDU(buf, 0, cmdLen + 5);
    }

    @Test
    public void TestSelectADF_PrimitiveDataObject() {
        init();
        byte sel[] = { 0x4F, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
                       0x4F, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x01}; // Sample BER format OID

        CommandAPDU apdu = encodeApdu((byte) INS_SELECT_ADF, sel, (short) sel.length);
        ResponseAPDU response = simulator.transmitCommand(apdu);
    }


    @Test
    public void TestSelectADF_ConstructedDataObject() {
        init();
        byte sel[] = { 0x61, 0x39, 0x4F, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
                       0x01, 0x00, 0x79, 0x07, 0x4F, 0x05, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x50, 0x0E,
                       0x49, 0x44, 0x2D, 0x4F, 0x6E, 0x65, 0x20, 0x50, 0x49, 0x56, 0x20, 0x42, 0x49, 0x4F,
                       0x5F, 0x50, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x6F, 0x62, 0x65, 0x72, 0x74, 0x68, 0x75,
                       0x72, 0x2E, 0x63, 0x6F, 0x6D, 0x7F, 0x66, 0x08, 0x02, 0x02, (byte) 0x80, 0x00, 0x02,
                       0x02, (byte) 0x80, 0x00 }; // Sample BER format OID

        CommandAPDU apdu = encodeApdu((byte) INS_SELECT_ADF, sel, (short) sel.length);
        //ResponseAPDU response = simulator.transmitCommand(apdu);
    }
}
