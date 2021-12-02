package com.android.fira.applet;

import com.android.ber.BerTlvBuilder;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class FiraTest {
    private CardSimulator simulator;
    private BerTlvBuilder berTlvBuilder;
    private CryptoManager mCryptoManager;

    public FiraTest() {
        simulator = new CardSimulator();
        berTlvBuilder = new BerTlvBuilder();
        mCryptoManager = new CryptoManager();
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
        buf[4] = 0;

        Util.setShort(buf, (short) 5, cmdLen);

        Util.arrayCopyNonAtomic(cmd, (short) 0, buf, (short) 7, cmdLen);
        return new CommandAPDU(buf, 0, cmdLen + 7);
    }

    private CommandAPDU encodeApdu(byte ins, byte[] cmd, short cmdLen, byte p1, byte p2) {
        byte[] buf = new byte[2500];
        buf[0] = (byte) 0x80;
        buf[1] = ins;
        buf[2] = p1;
        buf[3] = p2;
        buf[4] = 0;

        Util.setShort(buf, (short) 5, cmdLen);

        Util.arrayCopyNonAtomic(cmd, (short) 0, buf, (short) 7, cmdLen);
        return new CommandAPDU(buf, 0, cmdLen + 7);
    }

    @Test
    public void TestSelectADF_PrimitiveDataObject() {
        init();

        /* Test bytes to compare
        byte sel[] = { 0x4F, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
                       0x4F, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x01}; // Sample BER format OID
        */
        byte[] sel = new byte[26];

        byte[] tag = {0x4f};
        byte[] tlv1 = {(byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
        byte[] tlv2 = {(byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x01};
        short offset = 0;

        offset = berTlvBuilder.addTlv(sel, tag, tlv1, offset);
        offset = berTlvBuilder.addTlv(sel, tag, tlv2, offset);

        CommandAPDU apdu = encodeApdu((byte) Constant.INS_SELECT_ADF, sel, (short) sel.length);
        ResponseAPDU response = simulator.transmitCommand(apdu);
    }

    @Test
    public void TestSelectADF_ConstructedDataObject() {
        init();
        /* Test bytes to compare
        byte sel1[] = { 0x61, 0x39, 0x4F, 0x0B, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
                       0x01, 0x00, 0x79, 0x07, 0x4F, 0x05, (byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x50, 0x0E,
                       0x49, 0x44, 0x2D, 0x4F, 0x6E, 0x65, 0x20, 0x50, 0x49, 0x56, 0x20, 0x42, 0x49, 0x4F,
                       0x5F, 0x50, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x6F, 0x62, 0x65, 0x72, 0x74, 0x68, 0x75,
                       0x72, 0x2E, 0x63, 0x6F, 0x6D, 0x7F, 0x66, 0x08, 0x02, 0x02, (byte) 0x80, 0x00, 0x02,
                       0x02, (byte) 0x80, 0x00 }; // Sample BER format OID
        */

        byte[] sel = new byte[70];
        byte[] tlv1 = {(byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
        byte[] tag1 = {0x4f};
        byte[] tmpl1 = {0x61};
        byte[] tlv2 = {(byte) 0xA0, 0x00, 0x00, 0x03, 0x08};
        byte[] tag2 = {0x4f};
        byte[] tmpl2 = {0x79};
        byte[] tlv3 = {0x49, 0x44, 0x2D, 0x4F, 0x6E, 0x65, 0x20, 0x50, 0x49, 0x56, 0x20, 0x42, 0x49, 0x4F};
        byte[] tag3 = {0x50};
        byte[] tlv4 = {0x77, 0x77, 0x77, 0x2E, 0x6F, 0x62, 0x65, 0x72, 0x74, 0x68, 0x75, 0x72, 0x2E,
                       0x63, 0x6F, 0x6D};
        byte[] tag4 = {0x5f, 0x50};
        byte[] tlv5_6 = {(byte) 0x80, 0x00};
        byte[] tag5_6 = {0x02};
        byte[] tmpl5_6 = {0x7f, 0x66};

        { /* Create complex Data Object */
            short offset = 0;
            berTlvBuilder.startCOTag(offset);
            {
                offset = berTlvBuilder.addTlv(sel, tag1, tlv1, offset);

                berTlvBuilder.startCOTag(offset);
                {
                    offset = berTlvBuilder.addTlv(sel, tag2, tlv2, offset);
                }
                offset = berTlvBuilder.endCOTag(sel, tmpl2, offset);

                offset = berTlvBuilder.addTlv(sel, tag3, tlv3, offset);
                offset = berTlvBuilder.addTlv(sel, tag4, tlv4, offset);
            }
            offset = berTlvBuilder.endCOTag(sel, tmpl1, offset);

            berTlvBuilder.startCOTag(offset);
            {
                offset = berTlvBuilder.addTlv(sel, tag5_6, tlv5_6, offset);
                offset = berTlvBuilder.addTlv(sel, tag5_6, tlv5_6, offset);
            }
            offset = berTlvBuilder.endCOTag(sel, tmpl5_6, offset);
        }
        CommandAPDU apdu = encodeApdu((byte) Constant.INS_SELECT_ADF, sel, (short) sel.length);
        ResponseAPDU response = simulator.transmitCommand(apdu);
    }

    @Test
    public void TestCustomADFCommand() {
        init();

        byte[] sel = new byte[70];
        byte[] tlv1 = {(byte) 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00}; // OIDs
        byte[] tlv2 = {(byte) 0xA0, 0x01, 0x02}; // Instance UIDS
        // UWB Controlee info
        byte[] tlv3 = {0x01, 0x02}; //Version
        {
            byte[] tlv3_1 = {0x01, 0x02}; //Version
        }
        byte[] tlv4 = {(byte) 0xA0, 0x01, 0x03}; // UWB session data
        byte[] tlv5 = {(byte) 0xA0, 0x01, 0x04}; // Fira SC credential

        short offset = 0;
        offset = berTlvBuilder.addTlv(sel, Constant.OID, tlv1, offset);
        offset = berTlvBuilder.addTlv(sel, Constant.INSTANCE_UID, tlv2, offset);
        //offset = berTlvBuilder.AddTlv(sel, Constant., tlv3, offset);
        offset = berTlvBuilder.addTlv(sel, Constant.UWB_SESSION_DATA, tlv4, offset);


        CommandAPDU apdu = encodeApdu((byte) Constant.INS_SELECT_ADF, sel, (short) sel.length);
        ResponseAPDU response = simulator.transmitCommand(apdu);
    }

    @Test
    public void TestSwapAdfCmd() {
        byte[] adf = new byte[1024];
        byte[] adfTlv = new byte[1024];
        byte[] out = new byte[1051];

        init();

        /*
           swap payload has the following members
            1) OID
            2) UWB controlee information
            3) Secure Blob
         */

        /* Dummy Data in sequence */
        adf[0] = 2; adf[74] = 3; // UWB capabilities
        adf[75] = 4; adf[327] = 5; // UWB session data
        adf[328] = 6; adf[411] = 7; // AC objects

        short offset = 0; short encLength = 0; short pacsOffset = 0;
        {
            { // Add OID
                out[offset++] = 0x06;
                out[offset++] = 0x0A;
                // dummy OID number
                out[offset] = 1;
                out[offset + 9] = 9;
                offset += 10;
            }
            { // ADD UWB info, None data
                out[offset++] = (byte) 0xBF;
                out[offset++] = 0x70;
                out[offset++] = 0x00;
            }
            { // PACS profile here
                { // fill tags
                    out[offset++] = (byte) 0xDF;
                    out[offset++] = 0x51;
                }

                pacsOffset = offset;
                // calculate secure blob start
                {
                    offset = 0;
                    berTlvBuilder.startCOTag(offset);
                    {
                        offset = berTlvBuilder.addTlv(adfTlv, offset, (short) adfTlv.length,
                                Constant.FIRA_PHY_VERSION_RANGE, (short) 0, (short) Constant.FIRA_PHY_VERSION_RANGE.length,
                                adf, (short) 0, (short) 75);
                    }
                    offset = berTlvBuilder.endCOTag(adfTlv, Constant.UWB_CAPABILITIES, offset);


                    offset = berTlvBuilder.addTlv(adfTlv, offset, (short) adfTlv.length,
                            Constant.UWB_SESSION_DATA_VERSION, (short) 0, (short) Constant.UWB_SESSION_DATA_VERSION.length,
                            adf, (short) 75, (short) 253);

                    offset = berTlvBuilder.addTlv(adfTlv, offset, (short) adfTlv.length,
                            Constant.FIRA_SC_CREDENTIAL, (short) 0, (short) Constant.FIRA_SC_CREDENTIAL.length,
                            adf, (short) 328, (short) 84);
                    encLength = mCryptoManager.aesCBC128NoPadEncrypt(adfTlv, (short) 0, (short) 480, out,
                                                                (short) (pacsOffset + 3) /* length bytes 3 */);
                }
                // calculate secure blob end

                { // Fill length bytes
                    out[pacsOffset++] = (byte) 0x82;
                    out[pacsOffset++] = (byte) (encLength / (short)0x100);
                    out[pacsOffset++] = (byte) (encLength % (short)0x100);
                }
            }
        }

        CommandAPDU apdu = encodeApdu(Constant.INS_SWAP_ADF, out, (short) (encLength + pacsOffset), (byte)0x01, (byte)0x00);
        ResponseAPDU response = simulator.transmitCommand(apdu);
    }

    @Test
    public void TestImportAdfCmd() {
        byte[] adf = new byte[1024];
        byte[] adfTlv = new byte[1024];

        init();

        /* Dummy Data in sequence */
        adf[0] = 2; adf[74] = 3; // UWB capabilities
        adf[75] = 4; adf[327] = 5; // UWB session data
        adf[328] = 6; adf[411] = 7; // AC objects

        short offset = 0;
        {
            // Dummy data
            berTlvBuilder.startCOTag(offset);
            {
                offset = berTlvBuilder.addTlv(adfTlv, offset, (short) adfTlv.length,
                        Constant.FIRA_PHY_VERSION_RANGE, (short) 0, (short) Constant.FIRA_PHY_VERSION_RANGE.length,
                        adf, (short) 0, (short) 75);
            }
            offset = berTlvBuilder.endCOTag(adfTlv, Constant.UWB_CAPABILITIES, offset);


            offset = berTlvBuilder.addTlv(adfTlv, offset, (short) adfTlv.length,
                    Constant.UWB_SESSION_DATA_VERSION, (short) 0, (short) Constant.UWB_SESSION_DATA_VERSION.length,
                    adf, (short) 75, (short) 253);

            offset = berTlvBuilder.addTlv(adfTlv, offset, (short) adfTlv.length,
                    Constant.FIRA_SC_CREDENTIAL, (short) 0, (short) Constant.FIRA_SC_CREDENTIAL.length,
                    adf, (short) 328, (short) 84);
        }

        CommandAPDU apdu = encodeApdu(Constant.INS_IMPORT_ADF, adfTlv, offset, (byte)0x00, (byte)0x00);
        ResponseAPDU response = simulator.transmitCommand(apdu);
    }
}
