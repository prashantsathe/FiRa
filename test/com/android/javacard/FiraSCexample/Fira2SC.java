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

import com.android.javacard.SecureChannels.FiraSC;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Shareable;

public class Fira2SC extends Applet implements Shareable {

    private FiraSC mFiraSC;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        new Fira2SC().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public Fira2SC() {
        mFiraSC = new FiraSC(new ADF()); // multiple firaSC
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            // reset the SCP connection, if any
            mFiraSC.reset();
            sendSelectResponse(apdu);
            return;
        }
    }

    public short processFiRaSCDummyContext(byte[] buff, short buffOffset, short buffLen) {
        return mFiraSC.handleProtocolObject(buff, buffOffset, buffLen);
    }

    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        return this;
    }

    private void sendSelectResponse(APDU apdu) {
        short responseLength = 0;
        byte[] apdubuff = apdu.getBuffer();

        if (apdubuff[ISO7816.OFFSET_P1] != 0x04 || apdubuff[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

        // TODO - Add FCI information
        apdu.setOutgoingAndSend((short) 0, responseLength);
    }

    private void sendOutgoing(APDU apdu, byte[] buff, short buffOffset, short buffLength) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(buffLength);
        apdu.sendBytesLong(buff, buffOffset, buffLength);
    }
}