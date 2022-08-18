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

import javacard.framework.JCSystem;

public class SusException extends RuntimeException {

    public short[] mReason;
    public static SusException exception;

    private SusException() {
        mReason = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    }

    public static void throwIt(short reason) {
        instance();
        exception.mReason[(short) 0] = reason;
        throw exception;
    }

    public static SusException instance() {
        if (exception == null) {
            exception = new SusException();
        }
        return exception;
    }

    public void clear() {
        exception.mReason[(short) 0] = 1000; // Unknown code
    }

    public static short getReason() {
        return exception.mReason[0];
    }
}