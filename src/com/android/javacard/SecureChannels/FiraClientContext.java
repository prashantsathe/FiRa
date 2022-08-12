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

public abstract class FiraClientContext {
    //Key sets
    public static final byte BASE_KEY_SET = 0;
    public static final byte PRIVACY_KEY_SET = 1;
    public static final byte SC_KEY_SET = 2;
    public static final byte UWB_ROOT_KEY_SET = 3;

    //Events
    public static final byte EVENT_INVALID = -1;
    public static final byte EVENT_OID = 0;
    public static final byte EVENT_SECURE = 1;
    public static final byte EVENT_RDS = 2;

    public static final byte INVALID_VALUE = -1;

    // Input is OId. Returns set of KVNs if the adf identified by the oid can be selected else it
    // returns null.
    public abstract boolean selectAdf(byte[] oidBuf, short start, short len);

    // Return the supported kvn in the selected Adf of the type passed in the parameters.
    public abstract short getSelectedKvn(byte kvnType, byte[] buf, short index);

    // Input is key set kvn and output is key set. If the key set is not found then  it
    // returns INVALID_VAL else key set is copied in the buf starting at index and returns the length
    // of the key set. Key set is copied in BER TLV format, starting with key set tag as defined in
    // FiraApplet Specifications.
    public abstract short getKeySet(short kvn, byte[] buf, short index);

    // Return the PA Public Key
    public abstract short getCAPublicKey(byte kvn, byte[] buf, short index);

    // Return Applet Secret Key
    public abstract short getSDSecretKey(byte[] buf, short index);

    // Return Applet SD Certificate.
    public abstract short getSDCertificate(byte[] buf, short index);

    // Return the notification data and clear the pending notification. If no pending notification
    // then invalid value is returned.
    public abstract short getPendingEvent();
    public abstract void signal(short eventId);
}
