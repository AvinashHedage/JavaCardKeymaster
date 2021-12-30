package com.android.javacard.keymaster;

import com.android.javacard.seprovider.KMAttestationCert;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMSEProvider;
import javacard.framework.Util;

public class KMKeymintSpecification implements KMSpecification {

  public static final byte[] JAVACARD_KEYMINT_DEVICE = {
      0x4a, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64,
      0x4b, 0x65, 0x79, 0x6d, 0x69, 0x6e, 0x74,
      0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
  };
  private static final byte[] GOOGLE = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};

  private static final byte[] dec319999Ms ={(byte)0, (byte)0, (byte)0xE6, (byte)0x77,
      (byte)0xD2, (byte)0x1F, (byte)0xD8, (byte)0x18};

  private static final byte[] dec319999 = {
      0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
      0x39, 0x35, 0x39, 0x5a,
  };

  private static final byte[] jan01970 = {
      0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x5a,
  };

  @Override
  public short getHardwareInfo() {
    final byte version = 1;
    // Make the response
    short respPtr = KMArray.instance((short) 6);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMInteger.uint_16(KMError.OK));
    resp.add((short) 1, KMInteger.uint_8(version));
    resp.add((short) 2, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add(
        (short) 3,
        KMByteBlob.instance(
            JAVACARD_KEYMINT_DEVICE, (short) 0, (short) JAVACARD_KEYMINT_DEVICE.length));
    resp.add((short) 4, KMByteBlob.instance(GOOGLE, (short) 0, (short) GOOGLE.length));
    resp.add((short) 5, KMInteger.uint_8((byte) 1));
    return respPtr;
  }

  @Override
  public short makeKeyCharacteristics(short keyParams, short osVersion, short osPatch,
      short vendorPatch, short bootPatch, short origin, byte[] scratchPad) {
    short strongboxParams = KMKeyParameters.makeSbEnforced(
        keyParams, (byte) origin, osVersion, osPatch, vendorPatch, bootPatch, scratchPad);
    short teeParams = KMKeyParameters.makeTeeEnforced(keyParams, scratchPad);
    short swParams = KMKeyParameters.makeKeystoreEnforced(keyParams, scratchPad);
    //short emptyParam = KMArray.instance((short) 0);
    short keyCharacteristics = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.cast(keyCharacteristics).setStrongboxEnforced(strongboxParams);
    KMKeyCharacteristics.cast(keyCharacteristics).setKeystoreEnforced(swParams);
    KMKeyCharacteristics.cast(keyCharacteristics).setTeeEnforced(teeParams);
    return keyCharacteristics;
  }

  @Override
  public short makeKeyCharacteristicsForKeyblob(short swParams, short sbParams, short teeParams) {
    short keyChars = KMKeyCharacteristics.instance();
    short emptyParam = KMArray.instance((short) 0);
    emptyParam = KMKeyParameters.instance(emptyParam);
    KMKeyCharacteristics.cast(keyChars).setStrongboxEnforced(sbParams);
    KMKeyCharacteristics.cast(keyChars).setKeystoreEnforced(emptyParam);
    KMKeyCharacteristics.cast(keyChars).setTeeEnforced(teeParams);
    return keyChars;
  }

  @Override
  public short getKeyCharacteristicsExp() {
    return KMKeyCharacteristics.exp();
  }

  @Override
  public boolean isProvisionedAttestKeysSupported() {
    return false;
  }

  @Override
  public boolean canCreateEarlyBootKeys() {
    return false;
  }

  @Override
  public short getHardwareParamters(short sbParams, short teeParams) {
    return KMKeyParameters.makeHwEnforced(sbParams, teeParams);
  }

  @Override
  public short concatParamsForAuthData(short keyBlobPtr, short hwParams, short swParams,
      short hiddenParams, short pubKey) {
    short arrayLen = 2;
    if (pubKey != KMType.INVALID_VALUE) {
      arrayLen = 3;
    }
    short params = KMArray.instance((short) arrayLen);
    KMArray.cast(params).add((short) 0, KMKeyParameters.cast(hwParams).getVals());
    KMArray.cast(params).add((short) 1, KMKeyParameters.cast(hiddenParams).getVals());
    if (3 == arrayLen) {
      KMArray.cast(params).add((short) 2, pubKey);
    }
    return params;
  }

  @Override
  public boolean isFactoryAttestationSupported() {
    return false;
  }

  @Override
  public KMAttestationCert makeCommonCert(short swParams, short hwParams, short keyParams,
      byte[] scratchPad, KMSEProvider seProvider) {
    short alg = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, keyParams);
    boolean rsaCert = KMEnumTag.cast(alg).getValue() == KMType.RSA;
    KMAttestationCert cert = KMAttestationCertImpl.instance(rsaCert, seProvider);

    // Validity period must be specified
    short notBefore = KMKeyParameters.findTag(KMType.DATE_TAG, KMType.CERTIFICATE_NOT_BEFORE, keyParams);
    if(notBefore == KMType.INVALID_VALUE){
      KMException.throwIt(KMError.MISSING_NOT_BEFORE);
    }
    notBefore = KMIntegerTag.cast(notBefore).getValue();
    short notAfter = KMKeyParameters.findTag(KMType.DATE_TAG, KMType.CERTIFICATE_NOT_AFTER, keyParams);
    if(notAfter == KMType.INVALID_VALUE ){
      KMException.throwIt(KMError.MISSING_NOT_AFTER);
    }
    notAfter = KMIntegerTag.cast(notAfter).getValue();
    // VTS sends notBefore == Epoch.
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 8, (byte) 0);
    short epoch = KMInteger.instance(scratchPad, (short)0, (short)8);
    short end = KMInteger.instance(dec319999Ms, (short)0, (short)dec319999Ms.length);
    if(KMInteger.compare(notBefore, epoch) == 0){
      cert.notBefore(KMByteBlob.instance(jan01970, (short)0, (short)jan01970.length),
          true, scratchPad);
    }else {
      cert.notBefore(notBefore, false, scratchPad);
    }
    // VTS sends notAfter == Dec 31st 9999
    if(KMInteger.compare(notAfter, end) == 0){
      cert.notAfter(KMByteBlob.instance(dec319999, (short)0, (short)dec319999.length),
          true, scratchPad);
    }else {
      cert.notAfter(notAfter, false, scratchPad);
    }
    // Serial number
    short serialNum =
        KMKeyParameters.findTag(KMType.BIGNUM_TAG, KMType.CERTIFICATE_SERIAL_NUM, keyParams);
    if (serialNum != KMType.INVALID_VALUE) {
      serialNum = KMBignumTag.cast(serialNum).getValue();
    }else{
      serialNum= KMByteBlob.instance((short)1);
      KMByteBlob.cast(serialNum).add((short)0, (byte)1);
    }
    cert.serialNumber(serialNum);
    return cert;
  }

  @Override
  public short getNotAfter(short params) {
    return 0;
  }

  @Override
  public short getNotBefore(short params) {
    return 0;
  }

  @Override
  public short getIssuer() {
    return 0;
  }
}
