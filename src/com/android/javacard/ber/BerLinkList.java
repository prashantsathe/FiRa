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
package com.android.javacard.ber;

public class BerLinkList {
    private ListObj rootObj;
    private ListObj tailObj;
    private short size;

    public BerLinkList() {
        rootObj = tailObj = null;
        size = 0;
    }

    public void addToTop(BerTlv tlv) {
        /* TODO: memory allocation */
        ListObj obj = new ListObj();
        obj.tlv = tlv;
        obj.nextPtr = null;

        if (rootObj == null) {
            rootObj = obj;
            tailObj = obj;
        } else {
            obj.nextPtr = tailObj;
            rootObj     = obj;
        }
        size++;
    }

    public void addToBottom(BerTlv tlv) {
        /* TODO: memory allocation */
        ListObj obj = new ListObj();
        obj.tlv = tlv;
        obj.nextPtr = null;

        if (rootObj == null) {
            rootObj = obj;
            tailObj = obj;
        } else {
            tailObj.nextPtr = obj;
            tailObj         = obj;
        }
        size++;
    }

    public short sizeOfList() {
        return size;
    }

    private class ListObj {
        BerTlv tlv;
        ListObj nextPtr;
    }
}
