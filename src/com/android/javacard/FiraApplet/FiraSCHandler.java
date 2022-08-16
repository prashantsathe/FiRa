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

import com.android.javacard.SecureChannels.FiraSecureChannel;

public class FiraSCHandler {

    public static short handleProtocolObject(byte[] buf, short index, short len,
            FiraAppletContext context) {
        FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
        return channel.handleProtocolObject(buf, index, len);
    }

    public static short wrap(byte[] buf, short index, short len, FiraAppletContext context) {
        FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
        return channel.wrap(buf, index, len);
    }

    public static short unwrap(byte[] buf, short index, short len, FiraAppletContext context) {
        FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
        return channel.unwrap(buf, index, len);
    }

    public static void terminate(FiraAppletContext context) {
        FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
        channel.terminate();
    }

    // The secure channel will prepare select command
    public static short initiate(byte[] firaAppletAid, short start, short appletIdLen, byte[] buf,
            short index, short len, byte[] oidBuf, short oidStart, short oidEnd,
            FiraAppletContext context) {
        FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
        return channel.initiate(firaAppletAid, start, appletIdLen, oidBuf, oidStart, oidEnd, buf,
                index, len);
    }

    public static short getNotification(byte[] buf, short index, FiraAppletContext context,
            short[] retValues) {
        byte eventId = (byte) context.getPendingEvent();
        short eventDataLen = 0;

        if (eventId != FiraAppletContext.EVENT_INVALID
                && eventId != FiraAppletContext.EVENT_SECURE) {
            FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
            eventDataLen = channel.getEventData(eventId, buf, index);
            context.clearPendingEvent();
        }
        retValues[0] = eventId;
        return eventDataLen;
    }

    public static boolean isSecure(FiraAppletContext context) {
        boolean ret = false;

        if (context.getPendingEvent() == FiraAppletContext.EVENT_SECURE) {
            context.clearPendingEvent();
            ret = true;
        }
        return ret;
    }

    public static byte getProtocolType(FiraAppletContext context) {
        FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
        return channel.getProtocolType();
    }

    public static short generateRDS(byte[] buf, short index, short len, byte[] uwbSessIdBuf,
            short uwbSessIdBufOffset, FiraAppletContext context) {
        FiraSecureChannel channel = (FiraSecureChannel) context.getSecureChannel();
        // TODO Extended options not supported
        return channel.generateRds(buf, index, len, null, (short) 0, (short) 0,
                !context.isDefaultKeyGeneration(), context.isSessionKeyUsedForDerivation(),
                uwbSessIdBuf, uwbSessIdBufOffset);
    }
}
