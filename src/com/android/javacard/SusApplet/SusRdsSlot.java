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

import com.android.javacard.ber.BerArrayLinkList;
import com.android.javacard.ber.BerTlvBuilder;
import com.android.javacard.ber.BerTlvParser;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class SusRdsSlot {

    private static Object[] mBerTlvParser;
    private static BerTlvBuilder mBerTlvBuilder;
    private static byte[] mRdsInfo;
    private static byte[] mRdsInfoInPersistent;

    public SusRdsSlot() {

        mBerTlvParser = new Object[MAX_RDS_COUNT];

        for (short i = 0; i < MAX_RDS_COUNT; i++)
            mBerTlvParser[i] = new BerTlvParser();

        mBerTlvBuilder = new BerTlvBuilder();
        mRdsInfo = JCSystem.makeTransientByteArray((short) (MAX_RDS_COUNT * STORAGE_RDS_SIZE),
                JCSystem.CLEAR_ON_RESET);

        // if persistent storage is configured
        if (STORE_RDS_PERSISTENT_FLAG) {
            mRdsInfoInPersistent = new byte[STORAGE_RDS_SIZE * MAX_RDS_COUNT];
        }
    }

    public short parseAndVerifyRangingDataSet(short slotId, byte[] inputData, short offset,
            short length) {
        // Parse input data to BER library
        ((BerTlvParser) mBerTlvParser[slotId]).parse(inputData, offset, length);
        // verify Ranging data set
        return verifyRangingDataSet(slotId, inputData, offset, length);
    }

    /*
     * Table 6. SELECT Response
     * Tag              Length      Description
     * ------------------------------------------------------
     * ‘6F’             variable    SELECT Response Template
     *   ‘84’           variable    SUS Applet AID
     *   ‘A5’           variable
     *    ‘BF0C’        5
     *      ‘9F7E’      2           SUS Applet version
     *      ‘4C’        3           SUS Applet options (TBD)
     * Note: The SUS applet cannot be selected through the contactless interface.
     */
    public static short createSelectResponse(byte[] reponseBuffer, short reponseBufferOffset) {

        short responseBufferLength = (short) reponseBuffer.length;

        short offset = 0;
        {
            mBerTlvBuilder.startCOTag(offset);
            {
                // Assuming AID is not more than 64 bytes
                // To avoid the use of another array, use response data's last 128 bytes,
                // which is tempBuffer
                short aidLength = JCSystem.getAID().getBytes(reponseBuffer,
                        (short) (responseBufferLength - 128));

                offset = BerTlvBuilder.addTlv(reponseBuffer,
                        (short) (reponseBufferOffset + offset), responseBufferLength,
                        S_SUS_APPLET_AID, (short) 0, (short) S_SUS_APPLET_AID.length, reponseBuffer,
                        (short) (responseBufferLength - 128), aidLength);

                mBerTlvBuilder.startCOTag(offset);
                {
                    mBerTlvBuilder.startCOTag(offset);
                    {
                        offset = BerTlvBuilder.addTlv(reponseBuffer,
                                (short) (reponseBufferOffset + offset), responseBufferLength,
                                S_SUS_APP_VERSION, (short) 0, (short) S_SUS_APP_VERSION.length,
                                S_SUS_APP_VERSION_INFO, (short) 0,
                                (short) S_SUS_APP_VERSION_INFO.length);

                        offset = BerTlvBuilder.addTlv(reponseBuffer,
                                (short) (reponseBufferOffset + offset), responseBufferLength,
                                S_APPLET_OPTIONS, (short) 0, (short) S_APPLET_OPTIONS.length,
                                S_APPLET_OPTIONS_INFO, (short) 0,
                                (short) S_APPLET_OPTIONS_INFO.length);
                    }
                    offset = mBerTlvBuilder.endCOTag(reponseBuffer, S_BFOC, offset);
                }
                offset = mBerTlvBuilder.endCOTag(reponseBuffer, S_A5, offset);
            }
            offset = mBerTlvBuilder.endCOTag(reponseBuffer, S_RESPONSE_TEMPLATE, offset);
        }

        return offset;
    }

    /*
     * Verify RDS information based on following table
     * @return     :- Return UWB Session-Id Offset w.r.t(from) rdsOffset
     * 
     *  Table 4. RDS for SUS internal API
     *
     *  Tag      Length      Description M / O / C
     *  -------------------------------------------
     *  0xC0     16 or 32    UWB Session Key M
     *  0xC1     16 or 32    Responder-specific Sub-session key O
     *  0xC2     2           Proximity Distance O
     *  0xC3     2           Angle of Arrival (AoA) O
     *  0xC4     1-128       Client specific data O
     *  0xC5     var.        Reserved O
     *  0xC6     var.        Key Exchange Key Identifier O
     *  0xC7     var.        Reserved O
     *  0xC8-CD  var.        RFU O
     *  0xCE     5-16        Service Applet AID O
     *  0xCF     4           UWB Session ID M
     *  0xD0     N/A         Reserved N/A
     *  0xD1     N/A         Reserved N/A
     *  0xF0-F7  N/A         Reserved for Proprietary Usage O
     */
    private short verifyRangingDataSet(short slotId, byte[] rds, short rdsOffset, short rdsLength) {

        boolean uwbSessionKeyPresent = false, uwbSessionIdPresent = false;
        short retUwbSessionOffset = 0, rdsInfoOffset = (short) (slotId * STORAGE_RDS_SIZE);
        BerArrayLinkList bLinkList = ((BerTlvParser) mBerTlvParser[slotId]).getBerArrayLinkList();
        short ptrOffset = bLinkList.getFirstTLVInstance();

        while (ptrOffset != -1) {

            short tagOffset = (short) (bLinkList.getTagOffset(ptrOffset) + rdsOffset);

            if (rds[tagOffset] == RANGING_SESSION_KEY) {
                uwbSessionKeyPresent = true;
            } else if (rds[tagOffset] == UWB_SESSION_ID) {
                uwbSessionIdPresent = true;
                // Storing the sessionid offset here itself to avoid another loop
                retUwbSessionOffset = bLinkList.getValueOffset(ptrOffset);
                Util.setShort(mRdsInfo, (short) (rdsInfoOffset + O_UWB_SESSION_ID),
                        retUwbSessionOffset);
            } else if (rds[tagOffset] == KEY_EXCHANGE_KEY_ID) {
                // Storing the keyexchangeKeyid offset here itself to avoid another loop
                Util.setShort(mRdsInfo, (short) (rdsInfoOffset + O_KEY_EXCHANGE_ID),
                        bLinkList.getValueOffset(ptrOffset));
            } else if ((rds[tagOffset] < 0xC0 && rds[tagOffset] > 0xD1)
                    || (rds[tagOffset] < 0xF0 && rds[tagOffset] > 0xF7)) {
                ISOException.throwIt(SecureUwbService.ERROR_WRONG_DATA);
            }

            ptrOffset = bLinkList.getNextTag(ptrOffset);
        }

        if (uwbSessionKeyPresent == false || uwbSessionIdPresent == false)
            ISOException.throwIt(SecureUwbService.ERROR_WRONG_DATA);

        return retUwbSessionOffset;
    }

    private short decodeLengthField(byte[] buf, short offset) {

        if (buf[offset] == (byte) 0x82) {
            if (buf[(short) (offset + 1)] > (byte) 0x7F) {
                return -1;
            }
            return Util.getShort(buf, (short) (offset + 1));
        } else if (buf[offset] == (byte) 0x81) {
            return (short) (0x00FF & buf[(short) (offset + 1)]);
        } else if (buf[offset] <= (byte) 0x7F) {
            return (short) (0x00FF & buf[offset]);
        } else {
            return -1;
        }
    }

    private short getLengthFieldLength(short length) {

        if (length < 0) {
            return -1;
        } else if (length < 128) {
            return 1;
        } else if (length < 256) {
            return 2;
        } else {
            return 3;
        }
    }

    private void resetRdsInfo(short slotId) {
        Util.arrayFillNonAtomic(mRdsInfo, (short) (slotId * STORAGE_RDS_SIZE), STORAGE_RDS_SIZE,
                (byte) 0x00);

        if (STORE_RDS_PERSISTENT_FLAG)
            Util.arrayFill(mRdsInfoInPersistent, (short) (slotId * STORAGE_RDS_SIZE),
                    STORAGE_RDS_SIZE, (byte) 0x00);
    }

    private boolean compareKeyExchangeAppAid(short slotId, byte[] inBuffer,
            short keyExchangeAppAidOffset, short keyExchangeAppAidLength) {
        return 0 == Util.arrayCompare(inBuffer, keyExchangeAppAidOffset, mRdsInfo,
                (short) ((slotId * STORAGE_RDS_SIZE) + O_KEY_EXCHANGE_APP_ID),
                keyExchangeAppAidLength);
    }

    private boolean compareKeyExchangeKeyId(short slotId, byte[] inBuffer,
            short keyExchangeKeyIdOffset, short keyExchangeKeyIdLength) {
        short offsetmRds = (short) (slotId * STORAGE_RDS_SIZE);
        short keyExchangeKeyIDOffset = (short) (Util.getShort(mRdsInfo,
                (short) (offsetmRds + O_KEY_EXCHANGE_ID)) + O_RDS);

        return 0 == Util.arrayCompare(inBuffer, keyExchangeKeyIdOffset, mRdsInfo,
                (short) (offsetmRds + keyExchangeKeyIDOffset), keyExchangeKeyIdLength);
    }

    private boolean compareUwbSessionId(short slotId, byte[] inBuffer, short offset) {
        short offsetmRds = (short) (slotId * STORAGE_RDS_SIZE);
        short uwbSessionIdOffset = (short) (Util.getShort(mRdsInfo,
                (short) (offsetmRds + O_UWB_SESSION_ID)) + O_RDS);

        // UWB session ID size is fixed, 4 bytes.
        return 0 == Util.arrayCompare(inBuffer, offset, mRdsInfo,
                (short) (offsetmRds + uwbSessionIdOffset), (short) 4);
    }

    /*
     * Copy RDS information based on following table
     * 
     *  Table 8. GET RDS Response for P1 = ‘00’
     *
     *  Tag         Length      Description M/O/C
     *  ---------------------------------------------------------------
     *  ‘C1’to‘CF’  Var         As defined in Table 4 CM1
     *
     *  Table 9. GET RDS Response for P1 = ‘01’
     *
     *  Tag         Length      Description M/O/C
     *  ----------------------------------------------------------------
     *  ‘C1’to‘CF’  Var         As defined in Table 4 CM1
     *  ‘D0’        16 or 32    secDataProtectionKey (see [4]) M
     *  ‘D1’        16 or 32    secPrivacyKey (see [4]) M
     *
     *  secDataProtectionKey and secPrivacyKey are derivative keys of the UWB Session Key, and
     *  correspond to the identically-named keys
     */
    private short copyRdsInformation(short slotId, byte[] outBuffer, short outBufferOffset,
            byte p1) {

        BerArrayLinkList bLinkList = ((BerTlvParser) mBerTlvParser[slotId]).getBerArrayLinkList();
        short ptrOffsetStart = bLinkList.getFirstTLVInstance();
        short ptrOffsetEnd, copiedLength = 0, tagOffset;
        byte finalRdsRangeByte = (byte) (p1 == 0x01 ? SEC_PRIVACY_KEY : UWB_SESSION_ID);
        short offsetmRds = (short) (slotId * STORAGE_RDS_SIZE);

        while (ptrOffsetStart != -1) {

            ptrOffsetEnd = bLinkList.getNextTag(ptrOffsetStart);
            tagOffset = (short) (bLinkList.getTagOffset(ptrOffsetStart) + offsetmRds + O_RDS);

            if (mRdsInfo[tagOffset] >= RANGING_SESSION_KEY
                    && mRdsInfo[tagOffset] <= finalRdsRangeByte) {
                short destOffset = (short) (outBufferOffset + copiedLength);

                if (ptrOffsetEnd != -1) {
                    copiedLength += (Util.arrayCopyNonAtomic(mRdsInfo, tagOffset, outBuffer,
                            destOffset, (short) ((bLinkList.getTagOffset(ptrOffsetEnd) + offsetmRds
                                    + O_RDS) - tagOffset)) - destOffset);
                } else {
                    short lastTagLength = bLinkList.getTotalTlvLength(ptrOffsetStart);

                    copiedLength += (Util.arrayCopyNonAtomic(mRdsInfo, tagOffset, outBuffer,
                            destOffset, lastTagLength) - destOffset);
                }
            }

            ptrOffsetStart = ptrOffsetEnd;
        }

        // Note:- If STORE_RDS_PERSISTENT_FLAG is enabled, in case of power-off after flash
        //        memory erased, RDS recovery is not possible.
        resetRdsInfo(slotId);

        return copiedLength;
    }

    public void storeRangingDataSetInPersistent(short slotId) {
        short offsetmRds = (short) (slotId * STORAGE_RDS_SIZE);

        if (mRdsInfoInPersistent != null) {
            Util.arrayCopy(mRdsInfo, offsetmRds, mRdsInfoInPersistent, offsetmRds,
                    STORAGE_RDS_SIZE);
        }
    }

    public void storeRangingDataSet(short slotId, byte[] rds, short rdsOffset, short rdsLength) {

        short offsetmRds = (short) (slotId * STORAGE_RDS_SIZE);
        // Copy RDS data
        Util.arrayCopy(rds, rdsOffset, mRdsInfo, (short) (offsetmRds + O_RDS), rdsLength);
        Util.setShort(mRdsInfo, (short) (offsetmRds + O_RDS_LENGTH), rdsLength);

        // Copy Key exchange App id & size
        short appIdLength = JCSystem.getPreviousContextAID().getBytes(mRdsInfo,
                (short) (offsetmRds + O_KEY_EXCHANGE_APP_ID));
        Util.setShort(mRdsInfo, (short) (offsetmRds + O_KEY_EXCHANGE_APP_ID_SIZE), appIdLength);

        // set 'occupied'
        mRdsInfo[(short) (offsetmRds + O_OCCUPIED)] = 0x01;
    }

    public void setRdsInfoInTransient() {

        short offsetmRds = 0;

        for (short slotId = 0; slotId < MAX_RDS_COUNT; slotId++) {

            if (mRdsInfoInPersistent[(short) ((slotId * STORAGE_RDS_SIZE) + O_OCCUPIED)] == 0x01) {
                offsetmRds = (short) (slotId * STORAGE_RDS_SIZE);
                Util.arrayCopyNonAtomic(mRdsInfoInPersistent, (short) offsetmRds, mRdsInfo,
                        (short) offsetmRds, STORAGE_RDS_SIZE);
                // parse the RDS to ber
                ((BerTlvParser) mBerTlvParser[slotId]).parse(mRdsInfo,
                        (short) (offsetmRds + O_RDS),
                        Util.getShort(mRdsInfo, (short) (offsetmRds + O_RDS_LENGTH)));
            }
        }
    }

    public void deleteRangingDataSet(byte[] inBuffer, short inOffset, short inLength,
            byte[] tempBuff) {

        // Delete All RDS data
        if (inLength == 0) {

            for (short id = 0; id < MAX_RDS_COUNT; id++)
                if (mRdsInfo[(short) ((id * STORAGE_RDS_SIZE) + O_OCCUPIED)] == 0x01) // isSlotOccupied
                    resetRdsInfo(id);

        } else if (inBuffer[inOffset] == KEY_EXCHANGE_KEY_ID
                || inBuffer[inOffset] == UWB_SESSION_ID) {
            // If tag 'C6' is present, then this method shall delete all
            // the Ranging Data Sets associated to both the Application calling
            // this method and the specified Key Exchange Key Identifier

            // If tag 'CF' is present, then this method shall delete the Ranging Data Set
            // associated to both the Application calling this method and the specified
            // Session ID

            byte aidLength = JCSystem.getPreviousContextAID().getBytes(tempBuff, (short) 0);

            short valueLength = decodeLengthField(inBuffer, (short) (inOffset + 1));
            short valueOffset = (short) (1 + getLengthFieldLength(valueLength) + inOffset);

            for (short id = 0; id < MAX_RDS_COUNT; id++) {
                if (mRdsInfo[(short) ((id * STORAGE_RDS_SIZE) + O_OCCUPIED)] == 0x01 // isSlotOccupied
                        && ((inBuffer[inOffset] == KEY_EXCHANGE_KEY_ID
                                ? compareKeyExchangeKeyId(id, inBuffer, valueOffset, valueLength)
                                : compareUwbSessionId(id, inBuffer, valueOffset))
                                || compareKeyExchangeAppAid(id, tempBuff, (short) 0, aidLength))) {
                    resetRdsInfo(id);
                }
            }
        }
    }

    public short getAvailableSlotId() {

        short id;

        for (id = 0; id < MAX_RDS_COUNT; id++) {
            // Check for Free slot
            if (mRdsInfo[(short) ((id * STORAGE_RDS_SIZE) + O_OCCUPIED)] == 0x00)
                break;
        }

        if (id >= MAX_RDS_COUNT)
            ISOException.throwIt(ISO7816.SW_FILE_FULL);

        return id;
    }

    public static boolean checkAnyActiveSession() {

        for (short id = 0; id < MAX_RDS_COUNT; id++) {
            if (mRdsInfo[(short) ((id * STORAGE_RDS_SIZE) + O_OCCUPIED)] == 0x01)
                return true;
        }

        return false;
    }

    public void checkDuplicateSessionId(short slotException, byte[] rds, short uwbSessionIdOffset) {

        for (short id = 0; id < MAX_RDS_COUNT; id++) {
            if (id != slotException
                    && mRdsInfo[(short) ((id * STORAGE_RDS_SIZE) + O_OCCUPIED)] // is Slot Occupied
                            == 0x01 && compareUwbSessionId(id, rds, uwbSessionIdOffset)) {
                ISOException.throwIt(SecureUwbService.ERROR_DUPLICATE_SESSION_ID);
            }
        }
    }

    public void deleteRdsOnUwbSessionId(byte[] rds, short uwbSessionIdOffset) {

        for (short slotId = 0; slotId < MAX_RDS_COUNT; slotId++) {
            if (mRdsInfo[(short) ((slotId * STORAGE_RDS_SIZE) + O_OCCUPIED)] // is Slot Occupied
                    == 0x01 && compareUwbSessionId(slotId, rds, uwbSessionIdOffset)) {
                resetRdsInfo(slotId);
                return;
            }
        }

        // ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        SusException.throwIt(EXP_UNKNOWN_SESSION_ID);
    }

    public short processGetRdsDataOnUwbSessionId(byte[] rds, short uwbSessionIdOffset, byte p1,
            byte[] outBuffer, short outBufferOffse) {

        short slotId;

        for (slotId = 0; slotId < MAX_RDS_COUNT; slotId++) {
            if (mRdsInfo[(short) ((slotId * STORAGE_RDS_SIZE) + O_OCCUPIED)] // is Slot Occupied
                    == 0x01 && compareUwbSessionId(slotId, rds, uwbSessionIdOffset)) {
                break;
            }
        }

        if (slotId >= MAX_RDS_COUNT)
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);

        return copyRdsInformation(slotId, outBuffer, outBufferOffse, p1);
    }
}
