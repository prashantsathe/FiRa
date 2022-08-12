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
package com.android.javacard.SecureChannels;

import static com.android.javacard.SecureChannels.ScpConstant.*;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class Scp extends FiraSecureChannel {

    private static byte[] mActiveChannel;
    private static byte[] mScpState;
    private static Crypto mCrypto;

    private Scp11Lib mScp11Lib;
    private Scp3Lib mScp3Lib;
    private FiraClientContext mFiraClientContext;

    public Scp(FiraClientContext firaClientContext) {
        mFiraClientContext = firaClientContext;
        InitStaticFields();
        mScp3Lib = new Scp3Lib(mCrypto);
        mScp11Lib = new Scp11Lib(mCrypto, mScp3Lib, firaClientContext);
    }

    private void InitStaticFields() {
        // Check just one field for NULL
        if (mActiveChannel == null) {
            mActiveChannel = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
            mScpState = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
            mCrypto = new Crypto();
        }
    }

    /**
     * Get current protocol type which is 'SCP11C'
     *
     * @return current protocol type.
     */
    public byte getProtocolType() {
        // returning current implemented protocol
        return SCP11C;
    }

    /**
     * Handle incoming protocol object which includes instruction commands
     * 'PERFORM_SECURITY_OPERATION' and 'MUTUAL_AUTHENTICATE'
     *
     * @param apduBuff : incoming buffer array
     * @param apduBuffOffset : incoming buffer array
     * @param apduBuffLen : incoming buffer array
     *
     * @return length of receipt incase of 'MUTUAL_AUTHENTICATE' or '0' in case of
     *         'PERFORM_SECURITY_OPERATION', if successful
     */
    public short handleProtocolObject(byte[] apduBuff, short apduBuffOffset, short apduBuffLen) {
        byte p1 = apduBuff[(short) (apduBuffOffset + ISO7816.OFFSET_P1)];
        byte p2 = apduBuff[(short) (apduBuffOffset + ISO7816.OFFSET_P2)];
        short cDataOffset = (short) (apduBuff[(short) (apduBuffOffset + ISO7816.OFFSET_LC)] == 0 ? 7 : 5);
        short dataLen = 0;

        if (mActiveChannel[0] != FREE) {
            // Only one active session for scp11C per SD
            if (mActiveChannel[0] != (byte) (APDU.getCLAChannel() + 1)) 
                ISOException.throwIt(ANOTHER_SCP11C_SESSION_IS_ACTIVE);
        }

        switch (apduBuff[ISO7816.OFFSET_INS]) {

            case PERFORM_SECURITY_OPERATION:
                // Table 6-8/9: Control parameter p1/p2
                if ((p1 & 0x80) == 0x80 ||
                            (p2 & 0x80) == 0x80) {
                    // TODO: we are using extended Length implementation
                    // Command chaining not supported
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                // In case of new or existed connection if we receive PSO
                // reset the credentials
                mScp11Lib.reset();

                // verify certificates and their signatures
                if (!mScp11Lib.parseAndVerifySignature(apduBuff, (short) cDataOffset,
                        (short) (apduBuffLen - cDataOffset), p2, p1)) {
                    ISOException.throwIt(INCORRECT_VAL_IN_CMD);
                }
                mScpState[0] = PSO_STATE;
                break;

            case MUTUAL_AUTHENTICATE:
                // Check if PSO is completed or not
                if (mScpState[0] != PSO_STATE)
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

                if (apduBuff[ISO7816.OFFSET_P2] == 0)
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

                dataLen = mScp11Lib.parseAndVerifyCrtGenerateReceipt(apduBuff, (short) cDataOffset,
                        (short) (apduBuffLen - cDataOffset), (byte) (p2 & 0x7F),
                        (byte) (p1 & 0x7F), apduBuff, cDataOffset);

                mActiveChannel[0] = (byte) (APDU.getCLAChannel() + 1);
                mScpState[0] = START_DONE_STATE;
                mFiraClientContext.signal(FiraClientContext.EVENT_SECURE);
                // TODO: The receipt key shall be deleted after sending the receipt.
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        return dataLen;
    }

    /**
     * Wrap(encrypt) incoming 'buff' start from 'buffOffset' based on assigned
     * 'mSecurityLevel' having length 'buffLen'
     *
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     *
     * @return length of wrapped data in 'buff' starting from 'buffOffset'
     */
    public short wrap(byte[] buff, short buffOffset, short buffLen)
            throws ArrayIndexOutOfBoundsException, ISOException {

        /* FiRa peer to peer testing purpose , comment out on release*/
        return buffLen;
        //return mScp11Lib.wrap(buff, buffOffset, buffLen, true);
    }

    /**
     * Unwrap(decrypt) incoming 'buff' start from 'buffOffset' based on assigned
     * 'mSecurityLevel' having length 'buffLen'
     *
     * @param buff : incoming buffer array
     * @param buffOffset : start index of buff array
     * @param buffLen : buff length
     *
     * @return length of unwrapped data in 'buff' starting from 'buffOffset'
     */
    public short unwrap(byte[] buff, short buffOffset, short buffLen) throws ISOException {
//        For SCP11c, session replay is possible as the randomness of session keys only depends on an ephemeral
//        key pair generated by the OCE. Therefore, operations performed within an SCP11c session are controlled as
//        described below:
//        • The usage of PUT KEY, DELETE [key(s)], and SET STATUS commands shall not be allowed. The
//        STORE DATA command is allowed but should not be used to load keys out of a secure and controlled
//        environment. For use cases where keys need to be set up, it is recommended to use scenario #1 or
//        scenario #3 from [Amd A].
//        • If the Security Level is ANY_AUTHENTICATED, the usage of some APDU commands and TLVs/DGIs
//        in the STORE DATA command is only allowed if explicitly authorized by CERT.OCE.ECKA. See
//        Annex B and Table B-3 for details.
//        Only one SCP11c session per SD is allowed at a given time.
        if (buffLen == 0) {
            return 0;
        }

        /* FiRa peer to peer testing purpose, comment out on release*/
        return buffLen;
        //return mScp11Lib.unwrap(buff, buffOffset, buffLen, true);
    }

    /**
     * get current security level
     *
     * @return current security level
     */
    public byte getSecurityLevel() {
        return mScp11Lib.getSecurityLevel();
    }

    /**
     * terminate the current the session
     */
    public void terminate() {
        // resetting the active channel is enough
        mActiveChannel[0] = FREE;
        mScp11Lib.reset();
    }

    public short initiate(byte[] appletId, short start, short appletIdLen, byte[] oidBuf,
            short oidStart, short oidEnd, byte[] buf, short index, short len) {
        // TODO Auto-generated method stub
        return 0;
    }

    public short getEventData(byte eventId, byte[] buf, short index) {
        // TODO Auto-generated method stub
        return 0;
    }

    public short generateRds(byte[] output, short outputOffset, short outputLength,
            byte[] sessionKeyInfo, short sessionKeyInfoOffset, short sessionKeyInfoLen,
            boolean useSessionKeyInfo, boolean useAsDiversificationData,
            byte[] uwbSessionOrSubSessionID, short uwbSessionOrSubSessionIdOffset) {
        // TODO Auto-generated method stub
        return 0;
    }
}
