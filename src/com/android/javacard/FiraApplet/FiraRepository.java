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
package com.android.javacard.FiraApplet;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * The repository stores persistent and transient data. The persistent data
 * consists of applet and static and shared adf data. The data is stored as data
 * objects identified by tags. The adf tags are specified by FiraApplet. The
 * memory is partitioned in various parts and every part specific data segment
 * has max length and used length. The slot specific data is divided into static
 * and dynamic parts. Also, the non slot specific data is divided into shared
 * adf and applet specific parts. Slot specific adf data begins after shared
 * data which in turn begins after applet specific data.
 */
public class FiraRepository {

    // Fixed slots
    public static final byte ROOT_SLOT = 32;
    public static final byte APPLET_SLOT = 33;
    public static final byte PUT = 0;
    public static final byte DELETE = 1;

    // Slot Specific Adf Static Data
    static final short IMPL_SLOT_STATIC_ADF_DATA_MAX_SIZE =
            (short) ((FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT *
                    FiraSpecs.IMPL_ADF_STATIC_DATA_MAX_SIZE_PER_SLOT));
    private static final short PERSISTENCE_MEM_SIZE =
            (short) (FiraSpecs.IMPL_APPLET_SPECIFIC_DATA_MAX_SIZE +
                    FiraSpecs.IMPL_SHARED_ADF_DATA_MAX_SIZE + IMPL_SLOT_STATIC_ADF_DATA_MAX_SIZE);
    private static final short TRANSIENT_MEM_SIZE = (short) ((FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT
            * FiraSpecs.IMPL_ADF_EPHEMERAL_DATA_MAX_SIZE_PER_SLOT)
            + (FiraSpecs.IMPL_DYNAMIC_SLOT_MAX_COUNT
                    * (FiraSpecs.IMPL_ADF_STATIC_DATA_MAX_SIZE_PER_SLOT
                            + FiraSpecs.IMPL_ADF_EPHEMERAL_DATA_MAX_SIZE_PER_SLOT)));

    private static final byte STATIC_PART = 0;
    private static final byte EPHEMERAL_PART = 1;
    private final static byte FREE = (byte) 0x80;
    private final static byte RESERVED = 0;
    // Backup and restore file begins with magic word and then version.
    // This is followed by Persistent memory data.
    // Magic word for backup and restore file
    private final static byte[] FILE_FIRA = { 'F', 'I', 'R', 'A' };
    // Version for backup and restore file - 1.0, upper nibble 1 and lower nibble 0
    private final static byte FILE_VERSION = 0x10;
    // Persistent memory consists of following structure:
    // {
    //      Length of applet specific data; Applet specific data;
    //      Length of shared data; shared adf data;
    //      Length of static slot 0 data, static adf data;
    //      Length of static slot 1 data, static adf data;
    //      Length of static slot n data; static adf data;
    // }
    // length is always 2 bytes.
    private final static byte HEADER_LEN = 2;
    private static final byte APPLET_DATA_CURSOR = 0;
    private static short[] sRetValues;
    private static short[] sSlots;
    private static byte[] sPersistentMem;
    private static byte[] sTransientMem;

    public static void init() {
        sRetValues = JCSystem.makeTransientShortArray((short) 5, JCSystem.CLEAR_ON_DESELECT);
        // NOTE: for upgrade if new slots are added then they have to be added at the
        // end. The old data
        // must be backed up.
        sSlots = new short[(short) ((FiraSpecs.IMPL_DYNAMIC_SLOT_MAX_COUNT
                + FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT) * 2)];
        sPersistentMem = new byte[PERSISTENCE_MEM_SIZE];
        sTransientMem = JCSystem.makeTransientByteArray(TRANSIENT_MEM_SIZE, JCSystem.CLEAR_ON_RESET);
        initSlots(FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT, FiraSpecs.IMPL_DYNAMIC_SLOT_MAX_COUNT);
    }

    private static void initSlots(byte staticSlots, byte dynamicSlots) {
        byte i = 0;
        short pCursor = (short) (FiraSpecs.IMPL_APPLET_SPECIFIC_DATA_MAX_SIZE
                + FiraSpecs.IMPL_SHARED_ADF_DATA_MAX_SIZE);
        short tCursor = 0;
        staticSlots *= 2;
        dynamicSlots *= 2;
        byte maxSlots = (byte) (staticSlots + dynamicSlots);

        while (i < maxSlots) {
            if (i < staticSlots) {
                sSlots[(short) (i + STATIC_PART)] = pCursor;
                sPersistentMem[pCursor] |= FREE;
                pCursor += FiraSpecs.IMPL_ADF_STATIC_DATA_MAX_SIZE_PER_SLOT;
            } else {
                sSlots[(short) (i + STATIC_PART)] = tCursor;
                sTransientMem[tCursor] |= FREE;
                tCursor += FiraSpecs.IMPL_ADF_STATIC_DATA_MAX_SIZE_PER_SLOT;
            }
            sSlots[(short) (i + EPHEMERAL_PART)] = tCursor;
            sTransientMem[tCursor] |= (byte) 0x80;
            tCursor += FiraSpecs.IMPL_ADF_EPHEMERAL_DATA_MAX_SIZE_PER_SLOT;
            if (pCursor > PERSISTENCE_MEM_SIZE || tCursor > TRANSIENT_MEM_SIZE) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            i += 2;
        }
    }

    public static final void addMultipleDataObjects(byte[] buf, short index, short len,
            byte slotId) {
        short end = (short) (index + len);

        while (index < end) {
            index = FiraUtil.getNextTag(buf, index, len, true, sRetValues);
            addDataObject(buf, sRetValues[0], (short) (index - sRetValues[0]), slotId);
        }
    }

    public static void addDataObject(byte[] buf, short index, short len, byte slotId) {
        FiraUtil.readBERTag(buf, index, len, sRetValues);
        short tag = sRetValues[0];
        byte[] mem;

        if (slotId == APPLET_SLOT) {
            mem = getAppletData(tag, sRetValues);
        } else if (slotId == ROOT_SLOT) {
            mem = getSharedAdfData(tag, sRetValues);
        } else {
            mem = getSlotSpecificAdfData(tag, slotId, sRetValues);
        }
        short maxLen = sRetValues[0];
        short cursor = sRetValues[1];
        short usedLen = sRetValues[2];
        short start = (short) (cursor - HEADER_LEN);
        short i = (short) (cursor + usedLen);
        short end = (short) (start + maxLen);
        if ((short) (i + len) > end) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        i = Util.arrayCopyNonAtomic(buf, index, mem, i, len);
        setLength(mem, cursor, (short) (usedLen + len));
    }

    private static void setLength(byte[] mem, short dataSegment, short len) {
        if (mem[(short) (dataSegment - HEADER_LEN)] < 0) {
            return;
        }
        Util.setShort(mem, (short) (dataSegment - HEADER_LEN), len);
    }

    // function return values are same as 'getNextTag'
    // sRetValues[0] - start index of TLV object 
    // sRetValues[1] - tag id
    // sRetValues[2] - total tag length 
    // sRetValues[3] = start index of TLV value field.
    private static boolean isMoreThanOneTag(byte[] buf, short offset, short len) {
        // first read DO
        FiraUtil.getNextTag(buf, offset, len, true, sRetValues);

        short doLen = sRetValues[2]; // DO len
        // read the child tag
        if (doLen > 0) {
            short totalTagLen = (short) (FiraUtil.getNextTag(buf, sRetValues[3], sRetValues[2], true,
                    sRetValues) - sRetValues[0]);
            if (totalTagLen < doLen) {
                return true;
            }
            sRetValues[2] = totalTagLen;
        }
        return false;
    }

    private static short getNewDO(byte[] mem, short tagStart, short tagLen, byte[] buf,
            short offset, short len, short tagId) {
        // make sure buf is greater than or equal to maxLen, as new DO will be get copied at
        // the end of the buf
        short bufIndex = (short) buf.length;
        if (bufIndex < FiraSpecs.IMPL_ADF_EPHEMERAL_DATA_MAX_SIZE_PER_SLOT)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        // get DO
        FiraUtil.getNextTag(mem, tagStart, tagLen, true, sRetValues);
        short doTagId = sRetValues[1]; // DO tag id
        short totalTagLen = 0, nextIndex = 0;
        short mIndex = sRetValues[3];  // DO Value Index
        short mLen = sRetValues[2];    // DO Tag Length
        boolean match = false;

        while (mLen > 0) {
            nextIndex = FiraUtil.getNextTag(mem, mIndex, mLen, true, sRetValues);
            totalTagLen = (short) (nextIndex - sRetValues[0]);
            mIndex = nextIndex;

            if (tagId == sRetValues[1]) {
                bufIndex = FiraUtil.pushBytes(buf, bufIndex, buf, offset, len);
                match = true;
            } else {
                bufIndex = FiraUtil.pushBytes(buf, bufIndex, mem, sRetValues[0], totalTagLen);
            }
            mLen -= totalTagLen;
        }

        // add tag if not 'replace'
        if (!match) {
            bufIndex = FiraUtil.pushBytes(buf, bufIndex, buf, offset, len);
        }
        // finally add DO
        bufIndex = FiraUtil.pushBERLength(buf, bufIndex, (short) (buf.length - bufIndex));
        bufIndex = FiraUtil.pushBERTag(buf, bufIndex, doTagId);
        sRetValues[0] = (short) (buf.length - bufIndex); // return total length
        return bufIndex;
    }

    /* Note: If DO has more than one tag then entire DO get replaced with the desired buffer (buf)
     *       else desired tag will be get added or replaced based on tag presence in Slot data. 
     */
    public static void putData(short dataObjectTag, byte[] buf, short offset, short len,
            byte slotId) {
        // Read slot data
        byte[] mem;

        if (slotId == APPLET_SLOT) {
            mem = getAppletData(dataObjectTag, sRetValues);
        } else if (slotId == ROOT_SLOT) {
            mem = getSharedAdfData(dataObjectTag, sRetValues);
        } else {
            mem = getSlotSpecificAdfData(dataObjectTag, slotId, sRetValues);
        }
        short maxLen = sRetValues[0];
        short cursor = sRetValues[1];
        short usedLen = sRetValues[2];
        short dataEnd = (short) (cursor + usedLen);
        sRetValues[0] = sRetValues[1] = sRetValues[2] = sRetValues[3] = 0;
        // Read the tag from stored data
        short tagEnd = FiraSpecs.INVALID_VALUE;
        short tagStart = 0;
        short tagLen = 0;

        if (usedLen > 0) {
            tagEnd = FiraUtil.getTag(dataObjectTag, mem, cursor, usedLen, false, sRetValues);
        }

        if (tagEnd != FiraSpecs.INVALID_VALUE) {
            tagStart = sRetValues[0];
            tagLen = (short) (tagEnd - tagStart);

            // Check if DO has more than one tag
            if (!isMoreThanOneTag(buf, offset, len)) {
                // now 'sRetValues' contains first tag information present in the 'buf'
                offset = getNewDO(mem, tagStart, tagLen, buf, sRetValues[0], sRetValues[2],
                        sRetValues[1]);
                len = sRetValues[0];
            }
        }
        JCSystem.beginTransaction();
        perform(PUT, mem, cursor, usedLen, maxLen, tagStart, tagLen, buf, offset, len);
        JCSystem.commitTransaction();
    }

    // This method is not a transaction. The caller must invoke this method in a
    // transaction.
    public static void perform(byte opCode, byte[] mem, short memStart, short memLen,
            short memMaxLen, short tagStart, short tagLen, byte[] valBuf, short valStart,
            short valLen) {
        short memEnd = (short) (memStart + memLen);
        short tagEnd = (short) (tagStart + tagLen);
        short valEnd = (short) (valLen + valStart);

        switch (opCode) {
        case PUT: // add or replace
            if (tagLen == 0) {
                if ((short) (valLen + memLen) < memMaxLen) {
                    // Add the new tag at the end
                    Util.arrayCopyNonAtomic(valBuf, valStart, mem, memEnd, valLen);
                    memLen = (short) (memLen + valLen);
                } else { // error
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
            } else if (valLen < (short) (tagLen + (memMaxLen - memLen))) {
                // Replace the existing tag
                // delete the current data.
                tagStart = Util.arrayCopyNonAtomic(mem, tagEnd, mem, tagStart,
                        (short) (tagEnd - memEnd));
                memLen = (short) (memLen - tagLen);
                // paste the new data
                Util.arrayCopyNonAtomic(valBuf, valStart, mem, tagStart, valLen);
                memLen = (short) (memLen + valLen);
            } else {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            break;
        case DELETE:
            if (tagLen > 0) {
                Util.arrayCopyNonAtomic(mem, tagEnd, mem, tagStart, (short) (tagEnd - memEnd));
                memLen = (short) (memLen - tagLen);
            }
            break;
        }
        setLength(mem, memStart, memLen);
    }

    public static byte[] getSlotSpecificAdfData(short tag, byte slotId, short[] retVal) {
        switch (tag) {
        case FiraSpecs.TAG_UWB_CONTROLEE_INFO:
        case FiraSpecs.TAG_UWB_SESSION_DATA:
            retVal[0] = FiraSpecs.IMPL_ADF_EPHEMERAL_DATA_MAX_SIZE_PER_SLOT;
            retVal[1] = sSlots[(short) (EPHEMERAL_PART + (short) (slotId * 2))];
            retVal[2] = Util.getShort(sTransientMem, retVal[1]);
            retVal[1] += HEADER_LEN;
            return sTransientMem;
        case FiraSpecs.TAG_FIRA_SC_CRED:// TAG_ADF_PROVISIONING_CRED
        case FiraSpecs.TAG_STORED_ADF_PROVISIONING_CRED:
        case FiraSpecs.TAG_OID:
        case FiraSpecs.TAG_INSTANCE_ID:
        case FiraSpecs.TAG_ACCESS_CONDITIONS:
        case FiraSpecs.TAG_IMPORT_ADF_ACCESS_CONDITIONS:
        case FiraSpecs.TAG_EXTENDED_OPTIONS:
        case FiraSpecs.TAG_SERVICE_DATA:
        case FiraSpecs.TAG_CMD_ROUTE_INFO:
            retVal[0] = FiraSpecs.IMPL_ADF_STATIC_DATA_MAX_SIZE_PER_SLOT;
            retVal[1] = sSlots[(short) (STATIC_PART + (short) (slotId * 2))];
            retVal[2] = Util.getShort(sPersistentMem, retVal[1]);
            retVal[1] += HEADER_LEN;
            return sPersistentMem;
        default:
            break;
        }
        return null;
    }

    public static byte[] getSharedAdfData(short tag, short[] retVal) {
        switch (tag) {
        case FiraSpecs.TAG_UWB_CONTROLEE_INFO:
        case FiraSpecs.TAG_PA_RECORD:
            retVal[0] = FiraSpecs.IMPL_SHARED_ADF_DATA_MAX_SIZE;
            retVal[1] = FiraSpecs.IMPL_APPLET_SPECIFIC_DATA_MAX_SIZE;
            retVal[2] = Util.getShort(sPersistentMem, retVal[1]);
            retVal[1] += HEADER_LEN;
            return sPersistentMem;
        default:
            break;
        }
        return null;
    }

    public static byte[] getAppletData(short tag, short[] retVal) {
        switch (tag) {
        case FiraSpecs.TAG_MASTER_KEY:
        case FiraSpecs.TAG_DEVICE_UID:
        case FiraSpecs.TAG_APPLET_SECRET:
        case FiraSpecs.TAG_PA_LIST:
        case FiraSpecs.TAG_APPLET_CERT_STORE:
            retVal[0] = FiraSpecs.IMPL_APPLET_SPECIFIC_DATA_MAX_SIZE;
            retVal[1] = APPLET_DATA_CURSOR;
            retVal[2] = Util.getShort(sPersistentMem, retVal[1]);
            retVal[1] += HEADER_LEN;
            return sPersistentMem;
        default:
            break;
        }
        return null;
    }

    // Find a free slot is range slotStart - slotEnd and then reserve it.
    private static short reserveSlot(byte slotStart, byte slotEnd, byte[] mem) {
        slotStart *= 2;
        slotEnd *= 2;
        byte i = slotStart;

        while (i < slotEnd) {
            short cursor = sSlots[(short) (i + STATIC_PART)];
            if ((byte) (mem[cursor] & FREE) != 0) {
                mem[cursor] &= RESERVED;
                return (short) (i / 2);
            }
            i += 2;
        }
        return FiraSpecs.INVALID_VALUE;
    }

    // The static sSlots are from 0 to IMPL_STATIC_SLOT_MAX_COUNT
    public static short reserveStaticSlot() {
        return reserveSlot((byte) 0, FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT, sPersistentMem);
    }

    // The dynamic slots begin after static sSlots - so the range is
    // IMPL_STATIC_SLOT_MAX_COUNT to
    // IMPL_STATIC_SLOT_MAX_COUNT + IMPL_DYNAMIC_SLOT_MAX_COUNT
    public static short reserveDynamicSlot() {
        return reserveSlot(FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT,
                (byte) (FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT
                        + FiraSpecs.IMPL_DYNAMIC_SLOT_MAX_COUNT),
                sTransientMem);
    }

    public static void freeSlot(byte slotId) {
        short cursor = sSlots[(short) ((slotId * 2) + STATIC_PART)];
        byte[] mem = sPersistentMem;

        if (slotId > FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT) {
            mem = sTransientMem;
        }

        if ((byte) (mem[cursor] & FREE) == 0) {
            Util.arrayFillNonAtomic(mem, cursor, FiraSpecs.IMPL_ADF_STATIC_DATA_MAX_SIZE_PER_SLOT,
                    (byte) 0);
            mem[cursor] |= FREE;
            mem = sTransientMem;
            cursor = sSlots[(short) ((slotId * 2) + EPHEMERAL_PART)];
            Util.arrayFillNonAtomic(mem, cursor,
                    FiraSpecs.IMPL_ADF_EPHEMERAL_DATA_MAX_SIZE_PER_SLOT, (byte) 0);
        }
    }

    public static byte getSlotUsingOid(byte[] oid, short index, short len) {
        byte i = 0;
        while (i < FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT) {
            byte[] mem = getSlotSpecificAdfData(FiraSpecs.TAG_OID, i, sRetValues);
            short cursor = sRetValues[1];
            short usedLen = sRetValues[2];
            if (usedLen > 0) {
                short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_OID, mem, cursor, usedLen, false,
                        sRetValues);
                short tagStart = sRetValues[3];
                if (tagEnd != FiraSpecs.INVALID_VALUE
                      // len can beless than total oid len
                        && Util.arrayCompare(oid, index, mem, tagStart, len) == 0) {
                    return i;
                }
            }
            i++;
        }
        return FiraSpecs.INVALID_VALUE;
    }

    // This will only be used for static sSlots
    public static byte getSlot(byte[] oid, short index, short len) {
        byte i = 0;

        while (i < FiraSpecs.IMPL_STATIC_SLOT_MAX_COUNT) {
            byte[] mem = getSlotSpecificAdfData(FiraSpecs.TAG_OID, i, sRetValues);
            short cursor = sRetValues[1];
            short usedLen = sRetValues[2];

            if (usedLen > 0) {
                short tagEnd = FiraUtil.getTag(FiraSpecs.TAG_OID, mem, cursor, usedLen, false,
                        sRetValues);
                short tagStart = sRetValues[0];

                if (tagEnd != FiraSpecs.INVALID_VALUE
                        // len can beless than total oid len
                        && Util.arrayCompare(oid, index, mem, tagStart, len) == 0) {
                    return i;
                }
            }
            i++;
        }
        return FiraSpecs.INVALID_VALUE;
    }

    public static boolean isSlotFree(byte slot) {
        getSlotSpecificAdfData(FiraSpecs.TAG_OID, slot, sRetValues);
        return sRetValues[2] < 0;
    }

    public static boolean isSlotSelected(byte slot) {
        getSlotSpecificAdfData(FiraSpecs.TAG_UWB_CONTROLEE_INFO, slot, sRetValues);
        return sRetValues[2] < 0;
    }

    public static void selectAdf(byte slot) {
        byte[] mem = null;
        mem = getSlotSpecificAdfData(FiraSpecs.TAG_UWB_CONTROLEE_INFO, slot, sRetValues);

        if (sRetValues[2] > 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        mem[(short) (sRetValues[1] - HEADER_LEN)] &= 0x7F;
    }

    public static void deselectAdf(byte slot) {
        byte[] mem = getSlotSpecificAdfData(FiraSpecs.TAG_UWB_CONTROLEE_INFO, slot, sRetValues);

        if (sRetValues[2] < 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        mem[(short) (sRetValues[1] - HEADER_LEN)] |= 0x80;
    }

    public static void putSharedDataObject(byte[] buf, short index, short len) {
        FiraUtil.readBERTag(buf, index, len, sRetValues);
        short tag = sRetValues[0];
        putData(tag, buf, index, len, ROOT_SLOT);
    }

    public static void putAppletDataObject(short tag, byte[] buf, short index, short len) {
        //FiraUtil.readBERTag(buf, index, len, sRetValues);
        //short tag = sRetValues[0];
        putData(tag, buf, index, len, APPLET_SLOT);
    }

    public static short computePrimitiveDataSize() {
        return 0;
    }

    public static short computeObjectCount() {
        return (short) 2;
    }

    public static void onSave(Element element) {
        if (element == null)
            return;

        element.write(sSlots).write(sPersistentMem);
    }

    public static void onRestore(Element element) {
        if (element == null)
            return;

        sSlots = (short[]) element.readObject();
        sPersistentMem = (byte[]) element.readObject();
    }
}
