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

package com.android.javacard.SusApplet;

import static com.android.javacard.SusApplet.Constants.*;

import org.firaconsortium.sus.SecureUwbService;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.OnUpgradeListener;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

public class SusApplet extends Applet
        implements ExtendedLength, SecureUwbService, OnUpgradeListener {

    private static byte[] mTempBuffer; // Send buffer
    private static SusRdsSlot mSusRDSstorage;
    private static byte[] mResetFlag;

    private static Object[] SUPPORTED_APPLET_AIDS;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        new SusApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    private SusApplet() {
        // if persistent storage is configured
        if (STORE_RDS_PERSISTENT_FLAG) {
            mResetFlag = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
            // set mResetFlag
            mResetFlag[0] = 0x01;
        }

        mSusRDSstorage = new SusRdsSlot();

        mTempBuffer = JCSystem.makeTransientByteArray(TEMP_BUF_SIZE, JCSystem.CLEAR_ON_RESET);
        SUPPORTED_APPLET_AIDS = new Object[] {
                // FiRa example Applet
                (Object) new byte[] {(byte) 0xA0, 0x00, 0x00, 0x08, 0x67, 0x03, 0x04},
                (Object) new byte[] {(byte) 0xA0, 0x00, 0x00, 0x08, 0x67, 0x46, 0x41, 0x50, 0x00},
                // NOTE: Add here new KeyExchangeApplet AID
        };
    }

    private boolean isContactlessInterface() {

        final byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);

        if (protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A
                || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
            return true;
        } else {
            return false;
        }
    }

    private void checkCLA(byte cla, byte lowerBound, byte upperBound) {
        if (!(cla >= lowerBound && cla <= upperBound))
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    /**
     * Process get RDS data
     * 
     * @param buffer - input APDU buffer
     * @return - response length(short) of get RDS data.
     */
    private short processGetRdsData(byte[] buffer) {
        // Check UWB length
        if (buffer[ISO7816.OFFSET_LC] != 4)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        return mSusRDSstorage.processGetRdsDataOnUwbSessionId(buffer, (short) ISO7816.OFFSET_CDATA,
                buffer[ISO7816.OFFSET_P1], mTempBuffer, (short) 0);
    }

    /**
     * Process erase RDS data
     * 
     * @param buffer - input APDU buffer
     */
    private void processEraseRds(byte[] buffer) {
        // Check UWB length
        if (buffer[ISO7816.OFFSET_LC] != 4)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        mSusRDSstorage.deleteRdsOnUwbSessionId(buffer, ISO7816.OFFSET_CDATA);
    }

    public void process(APDU apdu) {

        byte securityLevel;
        short responseOffset = 0, responseLength = 0;

        // Check for contact less interface
        if (isContactlessInterface()) {
            return;
        }

        // if persistent storage is configured then check if reset happen
        if (STORE_RDS_PERSISTENT_FLAG && mResetFlag[0x00] != 0x01) {
            mSusRDSstorage.setRdsInfoInTransient();
            mResetFlag[0] = 0x01;
        }

        /* Note: The protocols support for SUS Applet are scp11.a and scp3 */
        SecureChannel sc = GPSystem.getSecureChannel();
        byte cardState = GPSystem.getCardState();
        byte[] apduBuf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        switch (apduBuf[ISO7816.OFFSET_INS]) {

        case INS_SELECT:

            checkCLA(apduBuf[ISO7816.OFFSET_CLA], (byte) 0x00, (byte) 0x03);

            if (apduBuf[ISO7816.OFFSET_P1] != 0x04 || apduBuf[ISO7816.OFFSET_P2] != 0x00)
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

            if (apduBuf[ISO7816.OFFSET_LC] != 0x09) // Check the size in document
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            responseLength = SusRdsSlot.createSelectResponse(mTempBuffer, (short) 0);
            sendOutgoing(apdu, responseLength);

            break;

        case INS_INT_AUTH: // Internal Authenticate
        case INS_PSO: // Process Security Operation

            if (cardState == GPSystem.CARD_OP_READY) {
                responseOffset = ISO7816.OFFSET_CDATA;
                responseLength = sc.processSecurity(apdu);
                apdu.setOutgoingAndSend(responseOffset, responseLength);
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            break;

        case INS_EXT_MUT_AUTH:

            if (apduBuf[ISO7816.OFFSET_P2] == 0x00) {
                if (cardState == GPSystem.SECURITY_DOMAIN_PERSONALIZED
                        || cardState == GPSystem.CARD_OP_READY) {
                    responseLength = sc.processSecurity(apdu);
                } else {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            } else {
                // SCP11 authentication only available in READY state
                if (cardState == GPSystem.CARD_OP_READY) {
                    responseLength = sc.processSecurity(apdu);
                    responseOffset = ISO7816.OFFSET_CDATA;
                } else {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }

            apdu.setOutgoingAndSend(responseOffset, responseLength);
            break;

        case INS_GET_RDS_DATA:

            checkCLA(apduBuf[ISO7816.OFFSET_CLA], (byte) 0x84, (byte) 0x87);

            if ((apduBuf[ISO7816.OFFSET_P1] < 0x00 && apduBuf[ISO7816.OFFSET_P1] > 0x01)
                    || apduBuf[ISO7816.OFFSET_P2] != 0x00)
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

            securityLevel = sc.getSecurityLevel();

            if (securityLevel == SUS_GP_SECURITY_LEVEL) {
                sc.unwrap(apduBuf, (short) 0,
                        (short) (ISO7816.OFFSET_CDATA + apdu.getIncomingLength()));
                responseLength = processGetRdsData(apduBuf);

                // Add Status to response buffer
                // GPC_2.2_D_SCP03_v1.0 section 6.2.5
                mTempBuffer[responseLength] = (byte)0x90;
                mTempBuffer[(short)(responseLength + 1)] = (byte)0x00;
                responseLength += 2;

                responseLength = sc.wrap(mTempBuffer, (short) 0, responseLength);
                sendOutgoing(apdu, responseLength);
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            break;

        case INS_ERASE_RDS:

            checkCLA(apduBuf[ISO7816.OFFSET_CLA], (byte) 0x84, (byte) 0x87);

            if (apduBuf[ISO7816.OFFSET_P1] != 0x00 || apduBuf[ISO7816.OFFSET_P2] != 0x00)
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

            securityLevel = sc.getSecurityLevel();

            if (securityLevel == SUS_GP_SECURITY_LEVEL) {
                sc.unwrap(apduBuf, (short) 0,
                        (short) (ISO7816.OFFSET_CDATA + apdu.getIncomingLength()));
                processEraseRds(apduBuf);

                // Add Status to response buffer
                // GPC_2.2_D_SCP03_v1.0 section 6.2.5
                mTempBuffer[(short)0] = (byte)0x90;
                mTempBuffer[(short)1] = (byte)0x00;

                responseLength = sc.wrap(mTempBuffer, (short) 0, (short) 2);
                sendOutgoing(apdu, responseLength);
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            break;

        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void sendOutgoing(APDU apdu, short length) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(mTempBuffer, (short) 0, length);
    }

    /*
     * Store RDS data specified in 'inBuffer' buffer, as per the availability of
     * slots. throw following exceptions javacard.framework.ISOException
     * - ERROR_WRONG_DATA
     * - ERROR_DUPLICATE_SESSION_ID
     *
     * @param inBuffer - byte array containing input data. Must be a global byte
     * array.
     * @param inOffset - offset of input data.
     * @param inLength - length of input data.
     * @param outBuffer, outOffset - N/A
     * @return - 0 (default)
     */
    public short createRangingDataSet(byte[] inBuffer, short inOffset, short inLength,
            byte[] outBuffer, short outOffset) {
        // Check RDS Length
        if (inLength > RDS_MAX_DATA_SIZE)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // Initial verification of AID is done in 'getShareableInterfaceObject'
        // Get free slot
        short slotId = mSusRDSstorage.getAvailableSlotId();

        // parse and verify incoming RDS information
        short uwbSessionIdOffset = (short) (mSusRDSstorage.parseAndVerifyRangingDataSet(slotId, inBuffer,
                inOffset, inLength) + inOffset);

        // Check for duplicate Session ID
        // NOTE: There could be duplicate session ids if more than one applet uses SUS
        // applet
        mSusRDSstorage.checkDuplicateSessionId(slotId, inBuffer, uwbSessionIdOffset);

        // we are throwing an exception in case of Memory full or validation fail,
        // so we should get slotId if above function returns back
        mSusRDSstorage.storeRangingDataSet(slotId, inBuffer, inOffset, inLength);

        // Store RDS in persistent memory
        if (STORE_RDS_PERSISTENT_FLAG) {
            mSusRDSstorage.storeRangingDataSetInPersistent(slotId);
        }

        return 0;
    }

    /**
     * Delete ranging data set as per input buffer tag information or no tag
     * information
     * 
     * @param inBuffer - byte array containing input data. Must be a global byte
     *                   array.
     * @param inOffset - offset of input data.
     * @param inLength - length of input data.
     * @param outBuffer, outOffset - N/A
     * @return - 0 (default)
     */
    public short deleteRangingDataSet(byte[] inBuffer, short inOffset, short inLength,
            byte[] outBuffer, short outOffset) {
        mSusRDSstorage.deleteRangingDataSet(inBuffer, inOffset, inLength, mTempBuffer);
        return 0;
    }

    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {

        if (isUpgrading()) return null;

        byte aidLength = clientAID.getBytes(mTempBuffer, (short) 0);

        // Verify the sender's AID
        for (short i = 0; i < SUPPORTED_APPLET_AIDS.length; i++) {
            if (aidLength == ((byte[])SUPPORTED_APPLET_AIDS[i]).length &&
                0 == Util.arrayCompare(mTempBuffer, (short) 0, (byte[]) SUPPORTED_APPLET_AIDS[i],
                        (short) 0, aidLength))
                return this;
        }

        return null;
    }

    private boolean isUpgrading() {
        return UpgradeManager.isUpgrading();
    }

    public void onCleanup() {
    }

    public void onConsolidate() {
    }

    public void onRestore(Element ele) {

        if (ele != null) {
            ele.initRead();
            short oldVersion = ele.readShort();

            // Check if Current version is greater than Old version
            if (CURRENT_PACKAGE_VERSION < oldVersion)
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    public Element onSave() {

        if (SusRdsSlot.checkAnyActiveSession())
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        // Create element.
        Element element = UpgradeManager.createElement(Element.TYPE_SIMPLE, (short) 2, (short) 0);

        if (element != null) {
            element.write(CURRENT_PACKAGE_VERSION);
        }

        return element;
    }

}
