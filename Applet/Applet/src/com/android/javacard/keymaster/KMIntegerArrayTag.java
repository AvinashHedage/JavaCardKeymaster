/*
 * Copyright(C) 2020 The Android Open Source Project
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

package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KMIntegerArrayTag extends KMTag {
  private static KMIntegerArrayTag prototype;
  private static short instPtr;

  private static final short[] tags = {USER_SECURE_ID};

  private KMIntegerArrayTag() {}

  private static KMIntegerArrayTag proto(short ptr) {
    if (prototype == null) prototype = new KMIntegerArrayTag();
    instPtr = ptr;
    return prototype;
  }

  public static short exp(short tagType) {
    if (!validateTagType(tagType)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short arrPtr = KMArray.exp(KMType.INTEGER_TYPE);
    short ptr = instance(TAG_TYPE, (short)6);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE), tagType);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+2), INVALID_TAG);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+4), arrPtr);
    return ptr;
  }

  public static short instance(short tagType, short key) {
    if (!validateTagType(tagType)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short arrPtr = KMArray.exp();
    return instance(tagType, key, arrPtr);
  }

  public static short instance(short tagType, short key, short arrObj) {
    if (!validateTagType(tagType)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if(heap[arrObj] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short ptr = instance(TAG_TYPE, (short)6);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE), tagType);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+2), key);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+4), arrObj);
    return ptr;
  }

  public static KMIntegerArrayTag cast(short ptr) {
    if (heap[ptr] != TAG_TYPE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    short tagType = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (!validateTagType(tagType)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getTagType() {
    return Util.getShort(heap, (short)(instPtr+TLV_HEADER_SIZE));
  }

  public short getKey() {
    return Util.getShort(heap, (short)(instPtr+TLV_HEADER_SIZE+2));
  }

  public short getValues() {
    return Util.getShort(heap, (short)(instPtr+TLV_HEADER_SIZE+4));
  }

  public short length() {
    short ptr = getValues();
    return KMIntegerArrayTag.cast(ptr).length();
  }

  public void add(short index, short val) {
    KMArray arr = KMArray.cast(getValues());
    arr.add(index, val);
  }

  public short get(short index) {
    KMArray arr = KMArray.cast(getValues());
    return arr.get(index);
  }

  private static boolean validateKey(short key) {
    short index = (short) tags.length;
    while (--index >= 0) {
      if (tags[index] == key) {
        return true;
      }
    }
    return false;
  }

  // TODO this should be combined with validateKey to actually validate {tagType, tagKey} pair.
  private static boolean validateTagType(short tagType) {
    if ((tagType == ULONG_ARRAY_TAG) || (tagType == UINT_ARRAY_TAG)) {
      return true;
    }
    return false;
  }
}
