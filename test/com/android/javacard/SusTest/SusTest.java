/*
 * Copyright(C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.SusTest;

import org.firaconsortium.sus.SecureUwbService;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/*
 * NOTE:-
 *       Valid command information
 *       CLA = 0x00
 *       INS = 0x00
 *       P1 = 00            --> deleteRangingDataSet
 *       p1 = 01-04         --> createRangingDataSet (each p1 value corresponds to unique UWB session ID)
 *       p2 = Any
 * 
 * This example is tested using UWBTestTool.jcsh file.
 * 
 */

public class SusTest extends Applet {

    // A0 00 00 08 67 53 55 53 00
    private final byte[] SUS_AID = new byte[] {
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x08, (byte) 0x67, (byte) 0x53,
            (byte) 0x55, (byte) 0x53, (byte) 0x00
    };

    /**
     * UWB Ranging Data Set.
     */
    private byte[] mRdsData;
    private byte[] rdstest = new byte[] {
            (byte)0xC0, 0x10, (byte)0xAD, 0x3B, 0x1C, 0x3C, (byte)0xD6, 0x1C, 0x62, 0x26,
            (byte)0x84, 0x67, (byte)0xF7, (byte)0xB4, 0x0B, 0x11, 0x38, 0x22, (byte)0xCF,
            0x04, (byte)0xAD, 0x3B, 0x1C, 0x3C
    };

    private SusTest() {
        mRdsData = JCSystem.makeTransientByteArray((short)54, JCSystem.CLEAR_ON_RESET);
        setDefaultRds();
    }

    private void setDefaultRds() {
        // Default dummy RDS data
        // mandatory 0xC0
        mRdsData[0] = (byte) 0xC0; mRdsData[1] = (byte) 0x20;
        mRdsData[2] = (byte) 0x00; mRdsData[3] = (byte) 0x00; mRdsData[4] = (byte) 0x00;
        mRdsData[5] = (byte) 0x00; mRdsData[6] = (byte) 0x00; mRdsData[7] = (byte) 0x00;
        mRdsData[8] = (byte) 0x00; mRdsData[9] = (byte) 0x00; mRdsData[10] = (byte) 0x00;
        mRdsData[11] = (byte) 0x00; mRdsData[12] = (byte) 0x00; mRdsData[13] = (byte) 0x00;
        mRdsData[14] = (byte) 0x00; mRdsData[15] = (byte) 0x00; mRdsData[16] = (byte) 0x00;
        mRdsData[17] = (byte) 0x00; mRdsData[18] = (byte) 0x00; mRdsData[19] = (byte) 0x00;
        mRdsData[20] = (byte) 0x00; mRdsData[21] = (byte) 0x00; mRdsData[22] = (byte) 0x00;
        mRdsData[23] = (byte) 0x00; mRdsData[24] = (byte) 0x00; mRdsData[25] = (byte) 0x00;
        mRdsData[26] = (byte) 0x00; mRdsData[27] = (byte) 0x00; mRdsData[28] = (byte) 0x00;
        mRdsData[29] = (byte) 0x00; mRdsData[30] = (byte) 0x00; mRdsData[31] = (byte) 0x00;
        mRdsData[32] = (byte) 0x00; mRdsData[33] = (byte) 0x00;
        // 0xC1
        mRdsData[34] = (byte) 0xC1; mRdsData[35] = (byte) 0x04;
        mRdsData[36] = (byte) 0x00; mRdsData[37] = (byte) 0x00; mRdsData[38] = (byte) 0x00;
        mRdsData[39] = (byte) 0x00;
        // 0xC2
        mRdsData[40] = (byte) 0xC2; mRdsData[41] = (byte) 0x02;
        mRdsData[42] = (byte) 0x00; mRdsData[43] = (byte) 0x00;
        // 0xC3
        mRdsData[44] = (byte) 0xC3; mRdsData[45] = (byte) 0x02;
        mRdsData[46] = (byte) 0x00; mRdsData[47] = (byte) 0x00;
        // mandatory 0xCF
        mRdsData[48] = (byte) 0xCF; mRdsData[49] = (byte) 0x04;
        mRdsData[50] = (byte) 0x01; mRdsData[51] = (byte) 0x02; mRdsData[52] = (byte) 0x03;
        mRdsData[53] = (byte) 0x04;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        new SusTest().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) throws ISOException {

        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            // in case of power reset, RDS set to 0. so setting up default value
            setDefaultRds();
            return;
        }

        AID aid = JCSystem.lookupAID(SUS_AID, (short)0, (byte)SUS_AID.length);
        SecureUwbService susInterface = (SecureUwbService)
                JCSystem.getAppletShareableInterfaceObject(aid, SecureUwbService.SERVICE_ID);


        switch (buffer[ISO7816.OFFSET_INS]) {

            case (byte) 0x00:
                {
                    switch (buffer[ISO7816.OFFSET_P1]) {

                        case 0x00:
                            susInterface.deleteRangingDataSet(buffer, ISO7816.OFFSET_CDATA,
                                    buffer[ISO7816.OFFSET_LC], null, (short) -1);
                            break;

                        case 0x01:
                        case 0x02:
                        case 0x03:
                        case 0x04:
                            // set First byte of UWB session id using p1 byte
                            mRdsData[50] = buffer[ISO7816.OFFSET_P1];
                            // A dummy data is put in the global buffer
                            Util.arrayCopyNonAtomic(mRdsData, (short) 0, buffer, (short) 0,
                                    (short) mRdsData.length);
                            // in-case of error createRangingDataSet triggers an exception
                            susInterface.createRangingDataSet(buffer, (short)0,
                                    (short)mRdsData.length, null, (short)0);
                            break;
                        
                        default:
                            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
                }

                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }

}
