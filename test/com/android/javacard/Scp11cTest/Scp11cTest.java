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
package com.android.javacard.Scp11cTest;

import static com.android.javacard.SecureChannels.ScpConstant.*;

import com.android.javacard.SecureChannels.Scp;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacardx.apdu.ExtendedLength;


/*
 * NOTE:-
 *       Valid command information
 *       CLA = 0x00
 *       INS = 0x00
 *       P1 = 00            --> deleteRangingDataSet
 *       p1 = 01-04         --> createRangingDataSet (each p1 value corresponds to unique UWB session ID)
 *       p2 = Any
 * 
 * This example is tested using scp11c.jcsh file.
 * 
 */

public class Scp11cTest extends Applet implements ExtendedLength {

    private Scp scp11c;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        new Scp11cTest().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public Scp11cTest() {
        scp11c = new Scp(new ADF());
    }

    public void process(APDU apdu) {
        short responseLength = 0, revLen = 0, bufLen = 0, cDataOffset = 0;
        // Good practice: Return 9000 on SELECT
        if (selectingApplet()) {
            return;
        }

        byte[] buf = apdu.getBuffer();
        revLen = apdu.setIncomingAndReceive();
        bufLen = apdu.getIncomingLength();
        cDataOffset = apdu.getOffsetCdata();

        switch (buf[ISO7816.OFFSET_INS]) {
        case (byte) PERFORM_SECURITY_OPERATION:
        case (byte) MUTUAL_AUTHENTICATE:
            // 0x2A..CLA => '80'-'87','C0'-'CF', or 'E0'-'EF' See [GPCS] section 11.1.4.
            // 0x82..CLA => '80'-'83' or 'C0'-'CF' See [GPCS] section 11.1.4. 
            responseLength = scp11c.handleProtocolObject(buf, (short) 0, (short) (cDataOffset + bufLen));
            apdu.setOutgoingAndSend(apdu.getOffsetCdata(), responseLength);
            break;
        case (byte) 0x2B:
            // unwrap is used by SD for internal calculation not for returning any data
            scp11c.unwrap(buf, (short) 0, (short) (cDataOffset + bufLen));
            break;
        case (byte) 0x2c:
            // sample code 'how to use unwrap/wrap'
            // if (securityLevel == SUS_GP_SECURITY_LEVEL) {
            //    sc.unwrap(apduBuf, (short) 0,
            //            (short) (ISO7816.OFFSET_CDATA + apdu.getIncomingLength()));
            //    responseLength = processGetRdsData(apduBuf);

            //    // Add Status to response buffer
            //    // GPC_2.2_D_SCP03_v1.0 section 6.2.5
            //    mTempBuffer[responseLength] = (byte)0x90;
            //    mTempBuffer[(short)(responseLength + 1)] = (byte)0x00;
            //    responseLength += 2;

            //    responseLength = sc.wrap(mTempBuffer, (short) 0, responseLength);
            //    sendOutgoing(apdu, responseLength);
            // }

            // send CDATA for wrapping (In SD it is used to send response, Keeping 0x9000 as per standard)
            buf[(short)(buf[ISO7816.OFFSET_LC] + cDataOffset)] = (byte)0x90;
            buf[(short)(buf[(short)ISO7816.OFFSET_LC] + 1 + cDataOffset)] = 0x00;
            responseLength = scp11c.wrap(buf, (short) cDataOffset, (short) (buf[ISO7816.OFFSET_LC] + 2));
            sendOutgoing(apdu, buf, (short) (responseLength + cDataOffset));
            break;
        default:
            // good practice: If you don't know the INStruction, say so:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void sendOutgoing(APDU apdu, byte[] buff, short length) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(buff, (short) 0, length);
    }
}