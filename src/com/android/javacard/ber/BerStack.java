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

import javacard.framework.JCSystem;

public class BerStack {

    private short[] mStack;
    private short[] mSize;
    private short[] mTop;
    private static final boolean SUCCESS = true;
    private static final boolean FAILURE = false;

    public BerStack(short stackSize) {
        mStack = JCSystem.makeTransientShortArray(stackSize, JCSystem.CLEAR_ON_DESELECT);

        mSize = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        mSize[0] = stackSize;

        mTop = JCSystem.makeTransientShortArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        mTop[0] = -1;
    }

    public boolean push(short value) {
        if (isFull()) {
            return FAILURE;
        }

        mStack[++mTop[0]] = value;
        return SUCCESS;
    }

    public short pop() {
        if(isEmpty()) {
            return -1;
        }

        return mStack[mTop[0]--];
    }

    public short size() {
        return (short) (mTop[0] + 1);
    }

    public boolean isEmpty() {
        return mTop[0] == -1;
    }

    public boolean isFull() {
        return mTop[0] == (short)(mSize[0] - 1);
    }

    public void resetStack() {
        mTop[0] = -1;
    }
}
