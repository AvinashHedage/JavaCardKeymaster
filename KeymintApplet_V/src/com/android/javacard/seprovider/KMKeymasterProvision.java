package com.android.javacard.seprovider;

import org.globalplatform.upgrade.Element;

import com.android.javacard.kmdevice.KMArray;
import com.android.javacard.kmdevice.KMInteger;
import com.android.javacard.kmdevice.KMKeyParameters;
import com.android.javacard.kmdevice.KMKeymasterDevice;
import com.android.javacard.kmdevice.KMRepository;
import com.android.javacard.kmdevice.KMTag;
import com.android.javacard.kmdevice.KMByteBlob;
import com.android.javacard.kmdevice.KMByteTag;
import com.android.javacard.kmdevice.KMDecoder;
import com.android.javacard.kmdevice.KMEnum;
import com.android.javacard.kmdevice.KMEnumArrayTag;
import com.android.javacard.kmdevice.KMEnumTag;

import javacard.framework.APDU;
import javacard.framework.Util;

public class KMKeymasterProvision {
	
//Provision reporting status
  private static final byte NOT_PROVISIONED = 0x00;
  private static final byte PROVISION_STATUS_ATTESTATION_KEY = 0x01;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_CHAIN = 0x02;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_PARAMS = 0x04;
  private static final byte PROVISION_STATUS_ATTEST_IDS = 0x08;
  private static final byte PROVISION_STATUS_PRESHARED_SECRET = 0x10;
  private static final byte PROVISION_STATUS_PROVISIONING_LOCKED = 0x20;
  private static final byte PROVISION_STATUS_DEVICE_UNIQUE_KEY = 0x40;
  private static final byte PROVISION_STATUS_ADDITIONAL_CERT_CHAIN = (byte) 0x80;
  private static final short POWER_RESET_MASK_FLAG = (short) 0x4000;
 
  public static final byte BOOT_KEY_MAX_SIZE = 32;
  public static final byte BOOT_HASH_MAX_SIZE = 32;
  public static final short SHARED_SECRET_KEY_SIZE = 32;
  protected static byte provisionStatus = NOT_PROVISIONED;
  
  protected KMKeymasterDevice kmDeviceInst;
  protected KMSEProvider seProvider;
  protected KMDecoder kmDecoder;
  protected KMRepository kmRepositroyInst;
  
  public short getBackupPrimitiveByteCount() {
	    // provisionStatus 
	    return (short) 1;
  }

  public short getBackupObjectCount() {
	    return (short) 0;
  }
  
  public void onSave(Element ele) {
    ele.write(provisionStatus);
  }

  public void onRestore(Element ele) {
	provisionStatus = ele.readByte();
  }
  
  public KMKeymasterProvision(KMKeymasterDevice deviceInst, KMSEProvider provider,  KMDecoder decoder, KMRepository repoInst){
	  kmDeviceInst = deviceInst;
	  seProvider = provider;
	  kmDecoder = decoder;
	  kmRepositroyInst = repoInst;
	}
	
  public void processSetBootParamsCmd(APDU apdu) {
    short argsProto = KMArray.instance((short) 5);
    
    byte[] scratchPad = apdu.getBuffer();
    // Array of 4 expected arguments
    // Argument 0 Boot Patch level
    KMArray.add(argsProto, (short) 0, KMInteger.exp());
    // Argument 1 Verified Boot Key
    KMArray.add(argsProto, (short) 1, KMByteBlob.exp());
    // Argument 2 Verified Boot Hash
    KMArray.add(argsProto, (short) 2, KMByteBlob.exp());
    // Argument 3 Verified Boot State
    KMArray.add(argsProto, (short) 3, KMEnum.instance(KMType.VERIFIED_BOOT_STATE));
    // Argument 4 Device Locked
    KMArray.add(argsProto, (short) 4, KMEnum.instance(KMType.DEVICE_LOCKED));

    short args = kmDeviceInst.receiveIncoming(apdu, argsProto);

    short bootParam = KMArray.get(args, (short) 0);

    ((KMAndroidSEProvider) seProvider).setBootPatchLevel(KMInteger.getBuffer(bootParam),
        KMInteger.getStartOff(bootParam),
        KMInteger.length(bootParam));

    bootParam = KMArray.get(args, (short) 1);
    if (KMByteBlob.length(bootParam) > BOOT_KEY_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    ((KMAndroidSEProvider) seProvider).setBootKey(KMByteBlob.getBuffer(bootParam),
        KMByteBlob.getStartOff(bootParam),
        KMByteBlob.length(bootParam));

    bootParam = KMArray.get(args, (short) 2);
    if (KMByteBlob.length(bootParam) > BOOT_HASH_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    ((KMAndroidSEProvider) seProvider).setVerifiedBootHash(KMByteBlob.getBuffer(bootParam),
        KMByteBlob.getStartOff(bootParam),
        KMByteBlob.length(bootParam));

    bootParam = KMArray.get(args, (short) 3);
    byte enumVal = KMEnum.getVal(bootParam);
    ((KMAndroidSEProvider) seProvider).setBootState(enumVal);

    bootParam = KMArray.get(args, (short) 4);
    enumVal = KMEnum.getVal(bootParam);
    ((KMAndroidSEProvider) seProvider).setDeviceLocked(enumVal == KMType.DEVICE_LOCKED_TRUE);

    
    // Clear the Computed SharedHmac and Hmac nonce from persistent memory.
    Util.arrayFillNonAtomic(scratchPad, (short) 0, KMRepository.COMPUTED_HMAC_KEY_SIZE, (byte) 0);
    seProvider.createComputedHmacKey(scratchPad, (short) 0, KMRepository.COMPUTED_HMAC_KEY_SIZE);
    
    kmDeviceInst.reboot();
    kmDeviceInst.sendError(apdu, KMError.OK);
  }
  
  public void processProvisionAttestationKey(APDU apdu) {
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT);
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 3);
    KMArray.add(argsProto, (short) 0, keyparams);
    KMArray.add(argsProto, (short) 1, keyFormatPtr);
    KMArray.add(argsProto, (short) 2, blob);

    short args = kmDeviceInst.receiveIncoming(apdu, argsProto);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();

    // key params should have os patch, os version and verified root of trust
    short keyParams = KMArray.get(args, (short) 0);
    keyFormatPtr = KMArray.get(args, (short) 1);
    short rawBlob = KMArray.get(args, (short) 2);
    // Key format must be RAW format
    short keyFormat = KMEnum.getVal(keyFormatPtr);
    if (keyFormat != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    //byte origin = KMType.IMPORTED;

    // get algorithm - only EC keys expected
    KMTag.assertPresence(keyParams, KMType.ENUM_TAG, KMType.ALGORITHM, KMError.INVALID_ARGUMENT);
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, keyParams);
    if (alg != KMType.EC) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // get digest - only SHA256 supported
    KMTag.assertPresence(keyParams, KMType.ENUM_ARRAY_TAG, KMType.DIGEST, KMError.INVALID_ARGUMENT);
    short len = KMEnumArrayTag.getValues(KMType.DIGEST, keyParams, scratchPad, (short) 0);
    if (len != 1) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (scratchPad[0] != KMType.SHA2_256) {
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    // Purpose should be ATTEST_KEY
    KMTag.assertPresence(keyParams, KMType.ENUM_ARRAY_TAG, KMType.PURPOSE,
        KMError.INVALID_ARGUMENT);
    len = KMEnumArrayTag.getValues(KMType.PURPOSE, keyParams, scratchPad, (short) 0);
    if (len != 1) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (scratchPad[0] != KMType.ATTEST_KEY) {
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
    // validate Curve
    KMTag.assertPresence(keyParams, KMType.ENUM_TAG, KMType.ECCURVE, KMError.INVALID_ARGUMENT);
    short curve = KMEnumTag.getValue(KMType.ECCURVE, keyParams);
    if (curve != KMType.P_256) {
      KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
    }
    // Decode EC Key
    short arrPtr = kmDeviceInst.decodeRawECKey(rawBlob);
    short secret = KMArray.get(arrPtr, (short) 0);
    short pubKey = KMArray.get(arrPtr, (short) 1);
    // Check whether key can be created
    seProvider.importAsymmetricKey(
        KMType.EC,
        KMByteBlob.getBuffer(secret),
        KMByteBlob.getStartOff(secret),
        KMByteBlob.length(secret),
        KMByteBlob.getBuffer(pubKey),
        KMByteBlob.getStartOff(pubKey),
        KMByteBlob.length(pubKey));

    // persist key
    seProvider.createAttestationKey(
        KMByteBlob.getBuffer(secret),
        KMByteBlob.getStartOff(secret),
        KMByteBlob.length(secret));
    
    provisionStatus |= PROVISION_STATUS_ATTESTATION_KEY;
    kmDeviceInst.sendError(apdu, KMError.OK);
  }  
  
  public void processProvisionAttestationCertDataCmd(APDU apdu) {
	    // TODO Handle this function properly
	kmDeviceInst.processAttestationCertDataCmd(apdu);
    provisionStatus |= (PROVISION_STATUS_ATTESTATION_CERT_CHAIN |
            PROVISION_STATUS_ATTESTATION_CERT_PARAMS);
        kmDeviceInst.sendError(apdu, KMError.OK);
  }
  
  public void processProvisionAttestIdsCmd(APDU apdu) {
    short keyparams = KMKeyParameters.exp();
    short cmd = KMArray.instance((short) 1);
    KMArray.add(cmd, (short) 0, keyparams);
    short args = kmDeviceInst.receiveIncoming(apdu, cmd);

    short attData = KMArray.get(args, (short) 0);
    // persist attestation Ids - if any is missing then exception occurs
    setAttestationIds(attData);
    provisionStatus |= PROVISION_STATUS_ATTEST_IDS;
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  public void processProvisionPreSharedSecretCmd(APDU apdu) {
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 1);
    KMArray.add(argsProto, (short) 0, blob);
    short args = kmDeviceInst.receiveIncoming(apdu, argsProto);

    short val = KMArray.get(args, (short) 0);

    if (val != KMType.INVALID_VALUE
        && KMByteBlob.length(val) != SHARED_SECRET_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Persist shared Hmac.
    ((KMAndroidSEProvider) seProvider).createPresharedKey(
        KMByteBlob.getBuffer(val),
        KMByteBlob.getStartOff(val),
        KMByteBlob.length(val));
    provisionStatus |= PROVISION_STATUS_PRESHARED_SECRET;
    kmDeviceInst.sendError(apdu, KMError.OK);

  }
  
  public void processGetProvisionStatusCmd(APDU apdu) {
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, KMInteger.uint_16(provisionStatus));
    kmDeviceInst.sendOutgoing(apdu, resp);
  }

  public void processLockProvisioningCmd(APDU apdu) {
    ((KMAndroidSEProvider) seProvider).setProvisionLocked(true);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }
  
  public void processProvisionDeviceUniqueKey(APDU apdu) {
	kmDeviceInst.sendError(apdu, KMError.CMD_NOT_ALLOWED); 	  
  }
  
  public void processProvisionAdditionalCertChain(APDU apdu) {
	kmDeviceInst.sendError(apdu, KMError.CMD_NOT_ALLOWED);	  
  }
  
  protected void setAttestationIds(short attIdVals) {
    short vals = KMKeyParameters.getVals(attIdVals);
    short index = 0;
    short length = KMArray.length(vals);
    short key;
    short type;
    short obj;
    while (index < length) {
      obj = KMArray.get(vals, index);
      key = KMTag.getKMTagKey(obj);
      type = KMTag.getKMTagType(obj);

      if (KMType.BYTES_TAG != type) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      obj = KMByteTag.getValue(obj);
      ((KMAndroidSEProvider) seProvider).setAttestationId(key, KMByteBlob.getBuffer(obj),
          KMByteBlob.getStartOff(obj),KMByteBlob.length(obj));
      index++;
    }
  }
  
//This function masks the error code with POWER_RESET_MASK_FLAG
  // in case if card reset event occurred. The clients of the Applet
  // has to extract the power reset status from the error code and
  // process accordingly.
  public short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 4);
    short powerResetStatus = 0;
    if (((KMAndroidSEProvider) seProvider).isPowerReset(true)) {
      powerResetStatus = POWER_RESET_MASK_FLAG;
    }

    Util.setShort(KMInteger.getBuffer(int32Ptr),
        KMInteger.getStartOff(int32Ptr),
        powerResetStatus);

    Util.setShort(KMInteger.getBuffer(int32Ptr),
        (short) (KMInteger.getStartOff(int32Ptr) + 2),
        err);
    // reset power reset status flag to its default value.
    //repository.restorePowerResetStatus(); //TODO
    return int32Ptr;
  }

}
