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
package com.android.javacard.FiraSCexample;

import static com.android.javacard.SecureChannels.FiraConstant.*;

import com.android.javacard.SecureChannels.FiraSC;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/*
 * NOTE:-
 *       Valid command information to initiate the fira SC1 communication 
 *       CLA = 0x00
 *       INS = 0x00
 *       P1 = 00
 *       p2 = Any
 * 
 */

public class Fira1SC extends Applet {

    private static final byte[] FIRA2_AID = new byte[] {
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x08, (byte) 0x67, (byte) 0x07,
            (byte) 0x01
    };

    private byte[] mInData;
    private Object[] mFiraSC;
    private ADF mADF;

    public Fira1SC() {
        mInData = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_RESET);
        mADF = new ADF();
        mFiraSC = JCSystem.makeTransientObjectArray((short) 3, JCSystem.CLEAR_ON_RESET);
        mFiraSC[0] = ((FiraSC) new FiraSC(mADF));
        mFiraSC[1] = ((FiraSC) new FiraSC(mADF));
        mFiraSC[2] = ((FiraSC) new FiraSC(mADF));
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        new Fira1SC().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        // Good practice: Return 9000 on SELECT
        if (selectingApplet()) {
            return;
        }

        AID aid = JCSystem.lookupAID(FIRA2_AID, (short) 0, (byte) FIRA2_AID.length);
        Fira2SC fira2Interface = (Fira2SC) JCSystem.getAppletShareableInterfaceObject(aid,
                (byte) 0x00);

        byte[] buf = apdu.getBuffer();

        switch (buf[ISO7816.OFFSET_INS]) {
        case (byte) 0x00:
            testFiRaSC(fira2Interface, buf, (short) 0, buf[ISO7816.OFFSET_INS]);
            break;
        default:
            // good practice: If you don't know the INStruction, say so:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void testFiRaSC(Fira2SC fira2Interface, byte[] buffer, short bufferOffset,
            byte asymmetricChannel) {
        short index = bufferOffset;
        short retLen = ERROR;
        short cnt = 4;
        // OIDs
        mInData[index++] = 0x06;
        mInData[index++] = 0x04; mInData[index++] = 0x01; mInData[index++] = 0x02;
        mInData[index++] = 0x03; mInData[index++] = 0x04;

        {
            // OID 1234 --> sc1 symmetric protocol

            // Initiate -> select command
            retLen = ((FiraSC) mFiraSC[0]).initiate(FIRA2_AID, (short) 0, (short) FIRA2_AID.length,
                    mInData, (short) 0, index, buffer, bufferOffset, (short) 1024);
            // send select command to RESPONDER
            // NOTE: As we are sending APDU through shared interfaces and above command generates
            //       select command, here we are assuming that fiRa2 applet is selected. now let's
            //       create select response(just 9000 reply) command in buffer from bufferOffset
            buffer[bufferOffset] = (byte) 0x90;
            buffer[(short) (bufferOffset + 1)] = (byte) 0x00;
            retLen = 2;

            // NOTE: FIRA sc protocol max has three subsequent commands
            //       We have to call "HandleProtocolObject' (max) 3 times till we
            //       get scp_status as CONNECTION_DONE. HandleProtocol throw exception
            //       on error
            while ((cnt--) > 0) {

                retLen = ((FiraSC) mFiraSC[0]).handleProtocolObject(buffer, bufferOffset, retLen);

                if (retLen > 0) {
                    if (((FiraSC) mFiraSC[0]).getSCPstatus() == CONNECTION_DONE) {
                        break;
                    }

                    // Dispatch the command to RESPONDER
                    retLen = fira2Interface.processFiRaSCDummyContext(buffer, bufferOffset, retLen);
                }
            }

            // if Connection is not established
            if (((FiraSC) mFiraSC[0]).getSCPstatus() != CONNECTION_DONE)
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

//        // OID 1235 --> sc1 asymmetric protocol
//        mInData[index++] = 0x05;
//        retLen = ((firaSC) mFiraSC[1]).initiate(null, (short) 0, (short) 0, mInData, (short) 0,
//                index, buffer, bufferOffset, (short) 1024);
//
//        // OID 1236 --> sc2 asymmetric protocol
//        mInData[index++] = 0x06;
//        retLen = ((firaSC) mFiraSC[2]).initiate(null, (short) 0, (short) 0, mInData, (short) 0,
//                index, buffer, bufferOffset, (short) 1024);
    }
}