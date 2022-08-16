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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class FiraInputValidation {

    // Types
    private static final byte BYTES = 0;
    private static final byte ENUM = 1;
    private static final byte STRUCTURE = 2;

    private static short decode(byte[] buf, short index, short len, boolean ordered, byte count,
            byte tagIndex, byte[] scratchPadBuf, short scratchPadIndex, short[] retValues) {
        if ((tagIndex != FiraSpecs.NO_IDX && FiraSpecs.expressionTable(tagIndex) == null)
                || (ordered && (count != 0))) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);// This should never happen
        }

        // Get the expression
        short type = getType(tagIndex);
        // Handle the tag based on its expected type.
        switch (type) {
        case ENUM:
            assertEnumValue(buf, index, len, FiraSpecs.expressionTable(tagIndex));
            index += len;
            break;
        case BYTES:
            index += len;
            break;
        case STRUCTURE:
            if (ordered) {
                assertOrderedStructure(buf, index, len, FiraSpecs.expressionTable(tagIndex), false,
                        scratchPadBuf, scratchPadIndex, retValues);
            } else {
                assertUnorderedStructure(buf, index, len, FiraSpecs.expressionTable(tagIndex),
                        count, false, scratchPadBuf, scratchPadIndex, retValues);
            }
            index += len;
            break;
        default:
            index = FiraSpecs.INVALID_VALUE;
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            break;
        }
        return index;
    }

    private static short getType(short tagIndex) {
        if (tagIndex == FiraSpecs.NO_IDX) {
            return BYTES;
        } else if (tagIndex >= FiraSpecs.ENUM_IDX_OFFSET) {
            return ENUM;
        } else {
            return STRUCTURE;
        }
    }

    private static void assertEnumValue(byte[] buf, short index, short len, short[] exp) {
        short end = (short) exp.length;
        byte i = 0;

        // Currently, only 2 bytes or 1 byte values are specified in FiraApplet Specs.
        if (len > 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short value = (len == 2) ? Util.getShort(buf, index) : buf[index];
        while (i < end) {
            if (value == exp[i]) {
                return;
            }
            i++;
        }
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    public static void assertUnorderedStructure(byte[] buf, short start, short len, short[] exp,
            byte count, boolean skip, byte[] scratchPadBuf, short scratchPad, short[] retValues) {
        short index = start;
        short end = (short) (start + len);

        // For un ordered set it may happen that count is less than all the elements in
        // the expression
        // In this case if the len of the incoming message is less than expression than
        // exit the loop
        // whenever either of them is done.
        while (index < end) {
            // Read the next tag - skip the 0s and FFs if desired.
            index = FiraUtil.getNextTag(buf, index, len, skip, retValues);
            short inTagStart = retValues[0];
            short inTag = retValues[1];
            short inLen = retValues[2];
            short valStart = retValues[3];
            // For an unordered structure, always compare expression list from the start
            short expIndex = getMatchingExpression(inTag, exp, (short) 0, false);

            if (expIndex == FiraSpecs.INVALID_VALUE) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            // If the tag matches with expression
            // Assert the length restriction
            assertLength(inLen, exp, expIndex);
            // decrement the count and check
            count--;

            if (count < 0) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }

            // Unordered structure cannot have unordered tags - this is according to
            // FiraApplet Specs
            // This check can be removed in future if required
            boolean ordered = getOrderAndCount(exp, expIndex, retValues);
            if (!ordered) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }

            // Decode the matching tag
            if (decode(buf, valStart, inLen, true, (byte) 0,
                    (byte) exp[(short) (expIndex + FiraSpecs.EXP_INDEX_OFFSET)], scratchPadBuf,
                    scratchPad, retValues) != index) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            if (len > 0) {
                len -= (short) (index - inTagStart);
            }
        }
    }

    public static void assertOrderedStructure(byte[] buf, short start, short len, short[] exp,
            boolean skip, byte[] scratchPadBuf, short scratchPad, short[] retValues) {
        short index = start;
        short end = (short) (start + len);
        short expIndex = 0;

        while (index < end) {
            // Read the next tag - skip the 0s and FFs if desired.
            index = FiraUtil.getNextTag(buf, index, len, skip, retValues);
            short inTagStart = retValues[0];
            short inTag = retValues[1];
            short inLen = retValues[2];
            short valStart = retValues[3];
            expIndex = getMatchingExpression(inTag, exp, expIndex, true);

            if (expIndex == FiraSpecs.INVALID_VALUE) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            // Assert the length restriction
            assertLength(inLen, exp, expIndex);

            // Get order restriction of current expression
            boolean ordered = getOrderAndCount(exp, expIndex, retValues);
            if (decode(buf, valStart, inLen, ordered, (byte) retValues[0],
                    (byte) exp[(short) (expIndex + FiraSpecs.EXP_INDEX_OFFSET)], scratchPadBuf,
                    scratchPad, retValues) != index) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            if (len > 0) {
                len -= (short) (index - inTagStart);
            }
            expIndex += FiraSpecs.EXP_ROW_SIZE;
        }
        // Assert remaining mandatory tags
        assertMandatoryTags(exp, expIndex);
    }

    private static void assertLength(short tagLength, short[] exp, short index) {
        short rule = exp[(short) (index + FiraSpecs.EXP_RULE_OFFSET)];
        boolean maxRule = (short) (rule & FiraSpecs.MAX) != 0;
        boolean eqRule = (short) (rule & FiraSpecs.LENGTH_RULE_MASK) == FiraSpecs.EQUAL;
        short len = (short) (rule & FiraSpecs.LENGTH_VAL_MASK);

        if ((maxRule && (tagLength > len)) || (eqRule && (tagLength != len))) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    private static void assertMandatoryTags(short[] exp, short expIndex) {
        while (expIndex < (short) exp.length) {
            if ((short) (exp[(short) (expIndex + FiraSpecs.EXP_RULE_OFFSET)]
                    & FiraSpecs.MANDATORY) != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            expIndex += FiraSpecs.EXP_ROW_SIZE;
        }
    }

    private static short getMatchingExpression(short tag, short[] exp, short index,
            boolean ordered) {
        while (index < (short) exp.length) {
            if (exp[(short) (index + FiraSpecs.EXP_TAG_OFFSET)] == tag) {
                return index;
            }
            if (ordered && ((short) (exp[(short) (index + FiraSpecs.EXP_RULE_OFFSET)]
                    & FiraSpecs.MANDATORY) != 0)) {
                break;
            }
            index += FiraSpecs.EXP_ROW_SIZE;
        }
        return FiraSpecs.INVALID_VALUE;
    }

    private static boolean getOrderAndCount(short[] exp, short expIndex, short[] retValues) {
        short rule = exp[(short) (expIndex + FiraSpecs.EXP_RULE_OFFSET)];
        boolean maxRule = (short) (rule & FiraSpecs.MAX) != 0;
        boolean ordered = (short) (rule & FiraSpecs.ORDER_RULE_MASK) == FiraSpecs.ORDERED;
        boolean countPresent = (short) (rule & FiraSpecs.COUNT) != 0;
        retValues[0] = 0;

        if (!ordered) {
            if (countPresent) {
                retValues[0] = (byte) (exp[(short) (expIndex + FiraSpecs.EXP_RULE_OFFSET)]
                        & FiraSpecs.LENGTH_VAL_MASK);
            } else if (maxRule) {
                retValues[0] = 100;
            } else {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
        }
        return ordered;
    }
}
