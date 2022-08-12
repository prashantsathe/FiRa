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

public abstract class FiraSecureChannel {
    public static final byte FIRA_SC_PROTOCOL = 0;
    public static final byte FIRA_SCP11c_PROTOCOL = 1;

    public abstract short initiate(byte[] appletId, short start, short appletIdLen, byte[] oidBuf,
            short oidStart, short oidEnd, byte[] buf,
            short index, short len);
    public abstract void terminate();
    public abstract short handleProtocolObject(byte[] buf, short index, short len);
    public abstract short wrap(byte[] buf, short index, short len);
    public abstract short unwrap(byte[] buf, short index, short len);
    public abstract byte getProtocolType();
    public abstract short getEventData(byte eventId, byte[] buf, short index);
    public abstract short generateRds(byte[] output, short outputOffset, short outputLength, byte[] sessionKeyInfo,
            short sessionKeyInfoOffset, short sessionKeyInfoLen, boolean useSessionKeyInfo,
            boolean useAsDiversificationData, byte[] uwbSessionOrSubSessionID, short uwbSessionOrSubSessionIdOffset);

    public static FiraSecureChannel create(byte type, FiraClientContext context) {
        if (type == FIRA_SC_PROTOCOL) {
            return new FiraSC(context);
        } else if(type == FIRA_SCP11c_PROTOCOL) {
            return new Scp(context);
        }
        return null;
    }
}
