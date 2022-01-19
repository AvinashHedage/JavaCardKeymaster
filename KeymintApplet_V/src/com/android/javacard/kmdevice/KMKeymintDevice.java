package com.android.javacard.kmdevice;

import com.android.javacard.seprovider.KMAttestationCert;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMSEProvider;

import javacard.framework.Util;
import javacard.security.CryptoException;

public class KMKeymintDevice extends KMKeymasterDevice {

  public static byte[] JAVACARD_KEYMINT_DEVICE;
  private static byte[] GOOGLE;

  private static byte[] dec319999Ms;

  private static byte[] dec319999;

  private static byte[] jan01970;

  public KMKeymintDevice(KMSEProvider seImpl, KMRepository repoInst, KMDecoder decoderInst) {
	super(seImpl, repoInst, decoderInst);
	initStatics();
  }
  
  public static void initStatics() {
    JAVACARD_KEYMINT_DEVICE = new byte[] {
	      0x4a, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64,
	      0x4b, 0x65, 0x79, 0x6d, 0x69, 0x6e, 0x74,
	      0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
	};
	GOOGLE = new byte[] {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};
	dec319999Ms = new byte[] {(byte) 0, (byte) 0, (byte) 0xE6, (byte) 0x77,
	      (byte) 0xD2, (byte) 0x1F, (byte) 0xD8, (byte) 0x18};
	dec319999 = new byte[] {
	      0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
	      0x39, 0x35, 0x39, 0x5a,
	  };
	jan01970 = new byte[] {
	      0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
	      0x30, 0x30, 0x30, 0x5a,
	  };
  }
  
  @Override
  public short getHardwareInfo() {
    final byte version = 1;
    // Make the response
    short respPtr = KMArray.instance((short) 6);
    KMArray.add(respPtr, (short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.add(respPtr, (short) 1, KMInteger.uint_8(version));
    KMArray.add(respPtr, (short) 2, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    KMArray.add(respPtr,
        (short) 3,
        KMByteBlob.instance(
            JAVACARD_KEYMINT_DEVICE, (short) 0, (short) JAVACARD_KEYMINT_DEVICE.length));
    KMArray.add(respPtr, (short) 4, KMByteBlob.instance(GOOGLE, (short) 0, (short) GOOGLE.length));
    KMArray.add(respPtr, (short) 5, KMInteger.uint_8((byte) 1));
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
    KMKeyCharacteristics.setStrongboxEnforced(keyCharacteristics, strongboxParams);
    KMKeyCharacteristics.setKeystoreEnforced(keyCharacteristics, swParams);
    KMKeyCharacteristics.setTeeEnforced(keyCharacteristics, teeParams);
    return keyCharacteristics;
  }

  @Override
  public short makeKeyCharacteristicsForKeyblob(short swParams, short sbParams, short teeParams) {
    short keyChars = KMKeyCharacteristics.instance();
    short emptyParam = KMArray.instance((short) 0);
    emptyParam = KMKeyParameters.instance(emptyParam);
    KMKeyCharacteristics.setStrongboxEnforced(keyChars, sbParams);
    KMKeyCharacteristics.setKeystoreEnforced(keyChars, emptyParam);
    KMKeyCharacteristics.setTeeEnforced(keyChars, teeParams);
    return keyChars;
  }

  @Override
  public short getKeyCharacteristicsExp() {
    return KMKeyCharacteristics.keymintExp();
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
    KMArray.add(params, (short) 0, KMKeyParameters.getVals(hwParams));
    KMArray.add(params, (short) 1, KMKeyParameters.getVals(hiddenParams));
    if (3 == arrayLen) {
      KMArray.add(params, (short) 2, pubKey);
    }
    return params;
  }

  @Override
  public short getSupportedAttestationMode(short attChallenge) {
	  // Attestation challenge present then it is an error because no factory provisioned attest key
	  short mode = KMType.NO_CERT; //TODO check what should be the default value
	  if (attChallenge != KMType.INVALID_VALUE && KMByteBlob.length(attChallenge) > 0) {
	    KMException.throwIt(KMError.ATTESTATION_KEYS_NOT_PROVISIONED);
	  }
	  if(KMEnumArrayTag.contains(KMType.PURPOSE, KMType.ATTEST_KEY, data[HW_PARAMETERS]) ||
	      KMEnumArrayTag.contains(KMType.PURPOSE, KMType.SIGN, data[HW_PARAMETERS])) {
	    mode = KMType.SELF_SIGNED_CERT;
	  }else{
	    mode = KMType.FAKE_CERT;
	  }
	  return mode;
  }

  @Override
  public KMAttestationCert makeCommonCert(short swParams, short hwParams, short keyParams,
      byte[] scratchPad, KMSEProvider seProvider) {
    short alg = KMKeyParameters.findTag(keyParams, KMType.ENUM_TAG, KMType.ALGORITHM);
    boolean rsaCert = KMEnumTag.getValue(alg) == KMType.RSA;
    KMAttestationCert cert = KMAttestationCertImpl.instance(rsaCert, seProvider);

    // Validity period must be specified
    short notBefore = KMKeyParameters.findTag(keyParams, KMType.DATE_TAG, KMType.CERTIFICATE_NOT_BEFORE);
    if (notBefore == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_NOT_BEFORE);
    }
    notBefore = KMIntegerTag.getValue(notBefore);
    short notAfter = KMKeyParameters.findTag(keyParams, KMType.DATE_TAG, KMType.CERTIFICATE_NOT_AFTER);
    if (notAfter == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_NOT_AFTER);
    }
    notAfter = KMIntegerTag.getValue(notAfter);
    // VTS sends notBefore == Epoch.
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 8, (byte) 0);
    short epoch = KMInteger.instance(scratchPad, (short) 0, (short) 8);
    short end = KMInteger.instance(dec319999Ms, (short) 0, (short) dec319999Ms.length);
    if (KMInteger.compare(notBefore, epoch) == 0) {
      cert.notBefore(KMByteBlob.instance(jan01970, (short) 0, (short) jan01970.length),
          true, scratchPad);
    } else {
      cert.notBefore(notBefore, false, scratchPad);
    }
    // VTS sends notAfter == Dec 31st 9999
    if (KMInteger.compare(notAfter, end) == 0) {
      cert.notAfter(KMByteBlob.instance(dec319999, (short) 0, (short) dec319999.length),
          true, scratchPad);
    } else {
      cert.notAfter(notAfter, false, scratchPad);
    }
    // Serial number
    short serialNum =
        KMKeyParameters.findTag(KMType.BIGNUM_TAG, KMType.CERTIFICATE_SERIAL_NUM, keyParams);
    if (serialNum != KMType.INVALID_VALUE) {
      serialNum = KMBignumTag.getValue(serialNum);
    } else {
      serialNum = KMByteBlob.instance((short) 1);
      KMByteBlob.add(serialNum, (short) 0, (byte) 1);
    }
    cert.serialNumber(serialNum);
    return cert;
  }

  @Override
  public short getMgf1Digest(short keyParams, short hwParams) {
    short mgfDigest = KMKeyParameters.findTag(keyParams, KMType.ENUM_ARRAY_TAG,
        KMType.RSA_OAEP_MGF_DIGEST);
    if (mgfDigest != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.length(mgfDigest) != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      mgfDigest = KMEnumArrayTag.get(mgfDigest, (short) 0);
      if (mgfDigest == KMType.DIGEST_NONE) {
        KMException.throwIt(KMError.UNSUPPORTED_MGF_DIGEST);
      }
      if (!KMEnumArrayTag
          .contains(KMType.RSA_OAEP_MGF_DIGEST, mgfDigest, hwParams)) {
        KMException.throwIt(KMError.INCOMPATIBLE_MGF_DIGEST);
      }
      if (mgfDigest != KMType.SHA1 && mgfDigest != KMType.SHA2_256) {
        KMException.throwIt(KMError.UNSUPPORTED_MGF_DIGEST);
      }
    }
    return mgfDigest;
  }

  @Override
  public void beginKeyAgreementOperation(KMOperationState op) {
    if (op.getAlgorithm() != KMType.EC)
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);

    op.setOperation(
        seProvider.initAsymmetricOperation(
            (byte) op.getPurpose(),
            (byte)op.getAlgorithm(),
            (byte)op.getPadding(),
            (byte)op.getDigest(),
            KMType.DIGEST_NONE, /* No MGF1 Digest */
            KMByteBlob.getBuffer(data[SECRET]),
            KMByteBlob.getStartOff(data[SECRET]),
            KMByteBlob.length(data[SECRET]),
            null,
            (short) 0,
            (short) 0));
  }
  
  @Override
  public void finishKeyAgreementOperation(KMOperationState op, byte[] scratchPad) {
    try {
      KMPKCS8Decoder pkcs8 = KMPKCS8Decoder.instance();
      short blob = pkcs8.decodeEcSubjectPublicKeyInfo(data[INPUT_DATA]);
      short len = op.getOperation().finish(
          KMByteBlob.getBuffer(blob),
          KMByteBlob.getStartOff(blob),
          KMByteBlob.length(blob),
          scratchPad,
          (short) 0
      );
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 32);
      Util.arrayCopyNonAtomic(
          scratchPad,
          (short) 0,
          KMByteBlob.getBuffer(data[OUTPUT_DATA]),
          KMByteBlob.getStartOff(data[OUTPUT_DATA]),
          len);
    } catch (CryptoException e) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }
 
  @Override
  public short getConfirmationToken(short confToken, short keyParams) {
    if (0 == KMByteBlob.length(confToken)) {
      KMException.throwIt(KMError.NO_USER_CONFIRMATION);
    }
    return confToken;
  }

  @Override
  public short getKMVerificationTokenExp() {
    return KMVerificationToken.timeStampTokenExp();
  }

  @Override
  public short getMacFromVerificationToken(short verToken) {
    return KMVerificationToken.getMac(verToken, (short) 0x02);
  }
  
  @Override
  public void validateECKeys() {
    // Read key size
    short eccurve = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if (eccurve == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    } else {
      if (eccurve != KMType.P_256) {
         KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
      }
    }
  }

}
