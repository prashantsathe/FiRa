package com.android.ber;

import javacard.framework.JCSystem;

public class BerStack {

    private short[] stack;
    private short size;
    private short top;
    private static final boolean SUCCESS = true;
    private static final boolean FAILURE = false;

    /*********** TODO: increase the stack run time ***********/

    public BerStack(short stackSize) {
        /* TODO check for max size */
        stack = JCSystem.makeTransientShortArray(stackSize, JCSystem.CLEAR_ON_DESELECT);
        size = stackSize;
        top = -1;
    }

    public boolean push(short value) {
        if (isFull()) {
            /* Error messages */
            return FAILURE;
        }

        stack[++top] = value;
        return SUCCESS;
    }

    /* NOTE:- current values that we stack, are positive short */
    public short pop() {
        if(isEmpty()) {
            /* Error Message */
            return -1;
        }

        return stack[top--];
    }

    public short size() {
        return (short) (top + 1);
    }

    public boolean isEmpty() {
        return top == -1;
    }

    public boolean isFull() {
        return top == (short)(size - 1);
    }
}
