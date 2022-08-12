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
package com.android.javacard.FiRaServiceApplet;

import javacard.framework.ISOException;
import javacard.framework.Shareable;

public interface FiRaServiceApplet extends Shareable {
  /**
   * Constant to be used as the {@code parameter} value in the call to
   * when requesting an instance of this interface from the Service Applet.
   */
  byte SERVICE_ID = (byte) 0xFA;
  /**
   * Method used by the FiRa Applet to pass the OID of the ADF calling the Service
   Applet.
   * The FiRa Applet may use the caller OID in order to allow or disallow access.
   * <p>
   * The input data shall be a single OID, encoded in ASN.1 format.
   * <p>
   * The applet implementing this method may throw an {@link ISOException} in case
   * processing fails (e.g. OID not accepted).
   *
   * @param inBuffer byte array containing input data. Must be a <em>global</em> byte
   * array.
   * @param inOffset offset of input data.
   * @param inLength length of input data.
   * @param outBuffer (Reserved For Future Use)
   * @param outOffset (Reserved For Future Use)
   * @return (Reserved For Future Use) 0
   * @throws NullPointerException if <code>inBuffer</code> is
   * <code>null</code>.
   * @throws SecurityException if <code>inBuffer</code> is not a
   * <em>global</em> byte array.
   * @throws ArrayIndexOutOfBoundsException if reading intput data would cause access
   * of data outside array bounds.
   * @throws ISOException if the applet implementing this methoddoes not accept the input
   */
 short setCallerOid(byte[] inBuffer, short inOffset, short inLength, byte[]
    outBuffer, short outOffset);
  /**
   * Used by the FiRa Applet to route APDU commands to the Service Applet.
   * <p> * The input data shall contain a full command to be processed by the
   Service Applet. If the command is encoded in ISO7816 APDU format,
   * the first byte shall be the Class byte.
   * <p>
   * If the Service Applet throws an exception, the FiRa Applet will abort the
   ongoing exchange with an error
   * <p>
   * @param inBuffer byte array containing input data. Must be a <em>global</em> byte
  array.
   * @param inOffset offset of input data.
   * @param inLength length of input data.
   * @param outBuffer byte array containing response data. Must be a <em>global</em>
  byte array.
   * @param outOffset offset of response data
   * @return length of response data, including 2 bytes for status code
   * @throws NullPointerException if either <code>inBuffer</code> or
  <code>outBuffer</code> is <code>null</code>.
   * @throws SecurityException if either <code>inBuffer</code> or
  <code>outBuffer</code> is not a <em>global</em> byte array.
   * @throws ArrayIndexOutOfBoundsException if reading input data or writing output
  data would cause access of data outside array bounds.
   * @throws ISOException with implementation specific error codes
   */
  short processFiRaServiceCommand(byte[] inBuffer, short inOffset, short
      inLength, byte[] outBuffer, short outOffset);
/**
 * Used by the FiRa Applet to notify end of processing and to trigger cleanup tasks
 * on the Service Applet.
 * <p>
 * The cleanup functionality is implementation specific. The FiRa Applet will
 * ignore any exceptions thrown by this method.
 */
  void processFiRaServiceCleanup();
}
