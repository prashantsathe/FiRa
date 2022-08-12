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

import com.android.javacard.ber.BerTlvParser;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class ClientContext {
  // FiRa keys/certificates functions list
  // Note: The OIDs are DER encoded.
  public static boolean getADFPrivacy(byte[] oidBuff, short oidBuffOffset, byte oidBuffLength) {
      return false;
  }

  public static short getADFdata(byte[] oidBuff, short oidBuffOffset, byte oidBuffLength,
          byte[] buffer, short bufferOffset) {
      return (short) (Util.arrayFillNonAtomic(buffer, bufferOffset, (short) 512,
              (byte) 0x02) - bufferOffset);
  }

  public static short getLabel(byte[] oidBuff, short oidBuffOffset, byte oidBuffLength,
          byte[] buffer, short bufferOffset) {
      buffer[bufferOffset++] = 0x01;
      buffer[bufferOffset++] = 0x02;
      buffer[bufferOffset++] = 0x03;
      buffer[bufferOffset++] = 0x04;
      return (short) 4;
  }

  // Table 74/75/76 of CSML CR v0.9_v123-TWG-May28-NXP-CSMLTT-NXP_ab.pdf
  public static short getFiRaCert2(byte[] buffer, short bufferOffset, FiraClientContext ctx) {
      return ctx.getSDCertificate(buffer, bufferOffset);
      /*
      short certSize = bufferOffset;

      // Default certificate TODO: remove it; used it for testing purpose
      // 7F2181D69310939393939393939393939393939393934207424242424242425F20102020202020202020202020202020202095020080
      // 5F2504201601015F240420260630530853535353535353537F4946B0410473103EC30B3CCF57DAAE08E93534AEF144A35940CF6BBB
      // A12A0CF7CBD5D65A64D82C8C99E9D3C45F9245BA9B27982C9AEA8EC1DB94B19C44795942C0EB22AA32F001005F3740CCEC7B0A621D
      // E21BF6840790ACE1B659599696D1EE473A3E80265B410AD6B3A472B2EA501D17C73E020EB0261ED5E854045BB9451B25EA2E684B3E
      // 731ED83C75

      buffer[certSize++] = 0x7f; buffer[certSize++] = 0x21; buffer[certSize++] = (byte) 0x81; buffer[certSize++] = (byte) 0xD6; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = 0x10;
      buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93;
      buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93;
      buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93; buffer[certSize++] = (byte) 0x93;
      buffer[certSize++] = (byte) 0x93; buffer[certSize++] = 0x42; buffer[certSize++] = 0x07; buffer[certSize++] = 0x42; buffer[certSize++] = 0x42;
      buffer[certSize++] = 0x42; buffer[certSize++] = 0x42; buffer[certSize++] = 0x42; buffer[certSize++] = 0x42; buffer[certSize++] = 0x42;
      buffer[certSize++] = 0x5f; buffer[certSize++] = 0x20; buffer[certSize++] = 0x10; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20;
      buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20;
      buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20;
      buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = 0x20; buffer[certSize++] = (byte) 0x95;
      buffer[certSize++] = 0x02; buffer[certSize++] = 0x00; buffer[certSize++] = (byte) 0x80; buffer[certSize++] = 0x5F; buffer[certSize++] = 0x25;
      buffer[certSize++] = 0x04; buffer[certSize++] = 0x20; buffer[certSize++] = 0x16; buffer[certSize++] = 0x01; buffer[certSize++] = 0x01;
      buffer[certSize++] = 0x5F; buffer[certSize++] = 0x24; buffer[certSize++] = 0x04; buffer[certSize++] = 0x20; buffer[certSize++] = 0x26;
      buffer[certSize++] = 0x06; buffer[certSize++] = 0x30; buffer[certSize++] = 0x53; buffer[certSize++] = 0x08; buffer[certSize++] = 0x53;
      buffer[certSize++] = 0x53; buffer[certSize++] = 0x53; buffer[certSize++] = 0x53; buffer[certSize++] = 0x53; buffer[certSize++] = 0x53;
      buffer[certSize++] = 0x53; buffer[certSize++] = 0x53; buffer[certSize++] = 0x7F; buffer[certSize++] = 0x49; buffer[certSize++] = 0x46;
      buffer[certSize++] = (byte) 0xB0; buffer[certSize++] = 0x41; buffer[certSize++] = 0x04; buffer[certSize++] = 0x73; buffer[certSize++] = 0x10;
      buffer[certSize++] = 0x3E; buffer[certSize++] = (byte) 0xC3; buffer[certSize++] = 0x0B; buffer[certSize++] = 0x3C; buffer[certSize++] = (byte) 0xCF;
      buffer[certSize++] = 0x57; buffer[certSize++] = (byte) 0xDA; buffer[certSize++] = (byte) 0xAE; buffer[certSize++] = 0x08; buffer[certSize++] = (byte) 0xE9;
      buffer[certSize++] = 0x35; buffer[certSize++] = 0x34; buffer[certSize++] = (byte) 0xAE; buffer[certSize++] = (byte) 0xF1; buffer[certSize++] = 0x44;
      buffer[certSize++] = (byte) 0xA3; buffer[certSize++] = 0x59; buffer[certSize++] = 0x40; buffer[certSize++] = (byte) 0xCF; buffer[certSize++] = 0x6B;
      buffer[certSize++] = (byte) 0xBB; buffer[certSize++] = (byte) 0xA1; buffer[certSize++] = 0x2A; buffer[certSize++] = 0x0C; buffer[certSize++] = (byte) 0xF7;
      buffer[certSize++] = (byte) 0xCB; buffer[certSize++] = (byte) 0xD5; buffer[certSize++] = (byte) 0xD6; buffer[certSize++] = 0x5A; buffer[certSize++] = 0x64;
      buffer[certSize++] = (byte) 0xD8; buffer[certSize++] = 0x2C; buffer[certSize++] = (byte) 0x8C; buffer[certSize++] = (byte) 0x99; buffer[certSize++] = (byte) 0xE9;
      buffer[certSize++] = (byte) 0xD3; buffer[certSize++] = (byte) 0xC4; buffer[certSize++] = 0x5F; buffer[certSize++] = (byte) 0x92; buffer[certSize++] = 0x45;
      buffer[certSize++] = (byte) 0xBA; buffer[certSize++] = (byte) 0x9B; buffer[certSize++] = 0x27; buffer[certSize++] = (byte) 0x98; buffer[certSize++] = 0x2C;
      buffer[certSize++] = (byte) 0x9A; buffer[certSize++] = (byte) 0xEA; buffer[certSize++] = (byte) 0x8E; buffer[certSize++] = (byte) 0xC1; buffer[certSize++] = (byte) 0xDB;
      buffer[certSize++] = (byte) 0x94; buffer[certSize++] = (byte) 0xB1; buffer[certSize++] = (byte) 0x9C; buffer[certSize++] = 0x44; buffer[certSize++] = 0x79;
      buffer[certSize++] = 0x59; buffer[certSize++] = 0x42; buffer[certSize++] = (byte) 0xC0; buffer[certSize++] = (byte) 0xEB; buffer[certSize++] = 0x22;
      buffer[certSize++] = (byte) 0xAA; buffer[certSize++] = 0x32; buffer[certSize++] = (byte) 0xF0; buffer[certSize++] = 0x01; buffer[certSize++] = 0x00;
      buffer[certSize++] = 0x5F; buffer[certSize++] = 0x37; buffer[certSize++] = 0x40; buffer[certSize++] = (byte) 0xCC; buffer[certSize++] = (byte) 0xEC;
      buffer[certSize++] = 0x7B; buffer[certSize++] = 0x0A; buffer[certSize++] = 0x62; buffer[certSize++] = 0x1D; buffer[certSize++] = (byte) 0xE2;
      buffer[certSize++] = 0x1B; buffer[certSize++] = (byte) 0xF6; buffer[certSize++] = (byte) 0x84; buffer[certSize++] = 0x07; buffer[certSize++] =(byte)  0x90;
      buffer[certSize++] = (byte) 0xAC; buffer[certSize++] = (byte) 0xE1; buffer[certSize++] = (byte) 0xB6; buffer[certSize++] = 0x59; buffer[certSize++] = 0x59;
      buffer[certSize++] = (byte) 0x96; buffer[certSize++] = (byte) 0x96; buffer[certSize++] = (byte) 0xD1; buffer[certSize++] = (byte) 0xEE; buffer[certSize++] = 0x47;
      buffer[certSize++] = 0x3A; buffer[certSize++] = 0x3E; buffer[certSize++] = (byte) 0x80; buffer[178] = 0x26; buffer[certSize++] = 0x5B;
      buffer[certSize++] = 0x41; buffer[certSize++] = 0x0A; buffer[certSize++] = (byte) 0xD6; buffer[183] = (byte) 0xB3; buffer[certSize++] = (byte) 0xA4;
      buffer[certSize++] = 0x72; buffer[certSize++] = (byte) 0xB2; buffer[certSize++] = (byte) 0xEA; buffer[188] = 0x50; buffer[certSize++] = 0x1D;
      buffer[certSize++] = 0x17; buffer[certSize++] = (byte) 0xC7; buffer[certSize++] = 0x3E; buffer[193] = 0x02; buffer[certSize++] = 0x0E;
      buffer[certSize++] = (byte) 0xB0; buffer[certSize++] = 0x26; buffer[certSize++] = 0x1E; buffer[certSize++] = (byte) 0xD5; buffer[certSize++] = (byte) 0xE8;
      buffer[certSize++] = 0x54; buffer[certSize++] = 0x04; buffer[certSize++] = 0x5B; buffer[certSize++] = (byte) 0xB9; buffer[certSize++] = 0x45;
      buffer[certSize++] = 0x1B; buffer[certSize++] = 0x25; buffer[certSize++] = (byte) 0xEA; buffer[certSize++] = 0x2E; buffer[certSize++] = 0x68;
      buffer[certSize++] = 0x4B; buffer[certSize++] = 0x3E; buffer[certSize++] = 0x73; buffer[certSize++] = 0x1E; buffer[certSize++] = (byte) 0xD8;
      buffer[certSize++] = 0x3C; buffer[certSize++] = 0x75; buffer[certSize++] = 0x00; buffer[certSize++] = 0x00; buffer[certSize++] = 0x00;

      return (short) (certSize - bufferOffset);
       */
  }

  public static short getKeyOffet(byte scIdentifier, byte keyType, byte[] keySetBuff,
          short keySetBuffOffset, short keySetBuffLen) {
      short offset = -1;
      short index = keySetBuffOffset;
      short totalLen = (short) (keySetBuffOffset + keySetBuffLen);
      boolean identifierMatch = false;
      short totalLengthByteCount = 0;

      // first byte must be of Constructed Tag
      if ((keySetBuff[index] & 0x20) != 0x20) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }

      // Header is always one byte (Table: 78/79/80)
      index += (BerTlvParser.getTotalLengthBytesCount(keySetBuff, (short) (index + 1)) + 1);

      while (index < totalLen) {

          // All tags of FiRa Secure Channel Credentials are 1 bytes
          totalLengthByteCount = BerTlvParser.getTotalLengthBytesCount(keySetBuff,
                  (short) (index + 1));

          if (keySetBuff[index] == (byte) 0x80
                  && scIdentifier == keySetBuff[(short) (index + totalLengthByteCount + 1)]) {
              identifierMatch = true;
          } else if (keyType == keySetBuff[index]) {
              offset = (short) (index + 2);
          }

          index += (1 + totalLengthByteCount +
                  BerTlvParser.getDataLength(keySetBuff, (short) (index + 1)));
      }

      if (offset == -1 || identifierMatch == false) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }

      return offset;
  }

  public static short getTagValueOffset(byte tag, byte[] keySetBuff, short keySetBuffOffset,
          short keySetBuffLen) {
      short offset = -1;
      short index = keySetBuffOffset;
      short totalLen = (short) (keySetBuffOffset + keySetBuffLen);
      short totalLengthByteCount = 0;

      // first byte must be of Constructed Tag
      if ((keySetBuff[index] & 0x20) != 0x20) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }

      // Header is always one byte (Table: 78/79/80)
      index += (BerTlvParser.getTotalLengthBytesCount(keySetBuff, (short) (index + 1)) + 1);

      while (index < totalLen) {

          // All tags of FiRa Secure Channel Credentials are 1 bytes
          totalLengthByteCount = BerTlvParser.getTotalLengthBytesCount(keySetBuff,
                  (short) (index + 1));

          if (keySetBuff[index] == tag) {
              offset = (short) (index + totalLengthByteCount + 1);
              break;
          }

          index += (1 + totalLengthByteCount + BerTlvParser.getDataLength(keySetBuff,
                  (short) (index + 1)));
      }

      return offset;
  }
  // FiRa keys/certificates functions list .. end

  // SCP11c keys/certificates function list
  public static short getPkCaKlocEcdsa(byte kvn, byte[] keyBuff, short keyBuffOffset,
      FiraClientContext ctx) {
      return ctx.getCAPublicKey(kvn,keyBuff,keyBuffOffset);

      /*
      // TODO: remove it; used it for testing purpose
      short index = keyBuffOffset;
      // Default keys
      // 0470cae1 25c051ef 3bb64feb df335fba 0c2d2782 d85337df 3ef904e9 2b744986 2bb56391 e433dcc7
      // dfafa19b ff6723e0 92ff55b8 95202a77 08952730 ac0844b3 fa
      keyBuff[index++] = 0x04; keyBuff[index++] = 0x70; keyBuff[index++] = (byte)0xca; keyBuff[index++] = (byte)0xe1;
      keyBuff[index++] = 0x25; keyBuff[index++] = (byte)0xc0; keyBuff[index++] = 0x51; keyBuff[index++] = (byte)0xef;
      keyBuff[index++] = 0x3b; keyBuff[index++] = (byte)0xb6; keyBuff[index++] = 0x4f; keyBuff[index++] = (byte)0xeb;
      keyBuff[index++] = (byte)0xdf; keyBuff[index++] = 0x33; keyBuff[index++] = 0x5f; keyBuff[index++] = (byte)0xba;
      keyBuff[index++] = 0x0c; keyBuff[index++] = 0x2d; keyBuff[index++] = 0x27; keyBuff[index++] = (byte)0x82;
      keyBuff[index++] = (byte)0xd8; keyBuff[index++] = 0x53; keyBuff[index++] = 0x37; keyBuff[index++] = (byte)0xdf;
      keyBuff[index++] = 0x3e; keyBuff[index++] = (byte)0xf9; keyBuff[index++] = 0x04; keyBuff[index++] = (byte)0xe9;
      keyBuff[index++] = 0x2b; keyBuff[index++] = 0x74; keyBuff[index++] = 0x49; keyBuff[index++] = (byte)0x86;
      keyBuff[index++] = 0x2b; keyBuff[index++] = (byte)0xb5; keyBuff[index++] = 0x63; keyBuff[index++] = (byte)0x91;
      keyBuff[index++] = (byte)0xe4; keyBuff[index++] = 0x33; keyBuff[index++] = (byte)0xdc; keyBuff[index++] = (byte)0xc7;
      keyBuff[index++] = (byte)0xdf; keyBuff[index++] = (byte)0xaf; keyBuff[index++] = (byte)0xa1; keyBuff[index++] = (byte)0x9b;
      keyBuff[index++] = (byte)0xff; keyBuff[index++] = 0x67; keyBuff[index++] = 0x23; keyBuff[index++] = (byte)0xe0;
      keyBuff[index++] = (byte)0x92; keyBuff[index++] = (byte)0xff; keyBuff[index++] = 0x55; keyBuff[index++] = (byte)0xb8;
      keyBuff[index++] = (byte)0x95; keyBuff[index++] = 0x20; keyBuff[index++] = 0x2a; keyBuff[index++] = 0x77;
      keyBuff[index++] = 0x08; keyBuff[index++] = (byte)0x95; keyBuff[index++] = 0x27; keyBuff[index++] = 0x30;
      keyBuff[index++] = (byte)0xac; keyBuff[index++] = 0x08; keyBuff[index++] = 0x44; keyBuff[index++] = (byte)0xb3;
      keyBuff[index++] = (byte)0xfa;

      return (short) (index - keyBuffOffset);
      */
  }

  public static short getSkSdEcka(byte kvn, byte[] keyBuff, short keyBuffOffset, FiraClientContext ctx) {
      short ret = ctx.getSDSecretKey(keyBuff,keyBuffOffset);
      if (ret == FiraClientContext.INVALID_VALUE) {
          return 0;
      }
      return ret;

      /*
      // TODO: remove it; used it for testing purpose
      // 04040404 04040404 04040404 04040404 04040404 04040404 04040404 04040404
      Util.arrayFillNonAtomic(keyBuff, keyBuffOffset, (short) 32, (byte) 0x04);
      return (short) 32;
      */
  }

  public static short getPkSdEcka(byte kvn, byte[] keyBuff, short keyBuffOffset) {
      short index = keyBuffOffset;

      // TODO: remove it; used it for testing purpose
      // 04 73103EC3 0B3CCF57 DAAE08E9 3534AEF1 44A35940 CF6BBBA1 2A0CF7CB D5D65A64
      // D82C8C99 E9D3C45F 9245BA9B 27982C9A EA8EC1DB 94B19C44 795942C0 EB22AA32
      keyBuff[index++] = 0x04; keyBuff[index++] = 0x73; keyBuff[index++] = 0x10; keyBuff[index++] = 0x3e;
      keyBuff[index++] = (byte)0xc3; keyBuff[index++] = 0x0b; keyBuff[index++] = 0x3c; keyBuff[index++] = (byte)0xcf;
      keyBuff[index++] = 0x57; keyBuff[index++] = (byte)0xda; keyBuff[index++] = (byte)0xae; keyBuff[index++] = 0x08;
      keyBuff[index++] = (byte)0xe9; keyBuff[index++] = 0x35; keyBuff[index++] = 0x34; keyBuff[index++] = (byte)0xae;
      keyBuff[index++] = (byte)0xf1; keyBuff[index++] = 0x44; keyBuff[index++] = (byte)0xa3; keyBuff[index++] = 0x59;
      keyBuff[index++] = 0x40; keyBuff[index++] = (byte)0xcf; keyBuff[index++] = 0x6b; keyBuff[index++] = (byte)0xbb;
      keyBuff[index++] = (byte)0xa1; keyBuff[index++] = 0x2a; keyBuff[index++] = 0x0c; keyBuff[index++] = (byte)0xf7;
      keyBuff[index++] = (byte)0xcb; keyBuff[index++] = (byte)0xd5; keyBuff[index++] = (byte)0xd6; keyBuff[index++] = 0x5a;
      keyBuff[index++] = 0x64; keyBuff[index++] = (byte)0xd8; keyBuff[index++] = 0x2c; keyBuff[35] = (byte)0x8c;
      keyBuff[index++] = (byte)0x99; keyBuff[index++] = (byte)0xe9; keyBuff[index++] = (byte)0xd3; keyBuff[index++] = (byte)0xc4;
      keyBuff[index++] = 0x5f; keyBuff[index++] = (byte)0x92; keyBuff[index++] = 0x45; keyBuff[index++] = (byte)0xba;
      keyBuff[index++] = (byte)0x9b; keyBuff[index++] = 0x27; keyBuff[index++] = (byte)0x98; keyBuff[index++] = 0x2c;
      keyBuff[index++] = (byte)0x9a; keyBuff[index++] = (byte)0xea; keyBuff[index++] = (byte)0x8e; keyBuff[index++] = (byte)0xc1;
      keyBuff[index++] = (byte)0xdb; keyBuff[index++] = (byte)0x94; keyBuff[index++] = (byte)0xb1; keyBuff[index++] = (byte)0x9c;
      keyBuff[index++] = 0x44; keyBuff[index++] = 0x79; keyBuff[index++] = 0x59; keyBuff[index++] = 0x42;
      keyBuff[index++] = (byte)0xc0; keyBuff[index++] = (byte)0xeb; keyBuff[index++] = 0x22; keyBuff[index++] = (byte)0xaa;
      keyBuff[index++] = 0x32;

      return (short) (index - keyBuffOffset);
  }

  public static boolean verifyCSN(byte[] csnBuff, short csnBuffOffset, short csnBuffLength) {
      return true;
  }
  // SCP11c keys/certificates function list .. end
}
