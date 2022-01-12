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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.OnUpgradeListener;
import org.globalplatform.upgrade.UpgradeManager;

import com.android.javacard.seprovider.KMAndroidSEProvider;
import com.android.javacard.seprovider.KMDeviceUniqueKey;
import com.android.javacard.seprovider.KMError;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMSEProvider;
import com.android.javacard.seprovider.KMType;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

public class KMAndroidSEApplet extends Applet implements AppletEvent, OnUpgradeListener, ExtendedLength {

  private static final byte KM_BEGIN_STATE = 0x00;
  private static final byte ILLEGAL_STATE = KM_BEGIN_STATE + 1;
  private static final short POWER_RESET_MASK_FLAG = (short) 0x4000;

  // Provider specific Commands
  private static final byte INS_KEYMINT_PROVIDER_APDU_START = 0x00;
  private static final byte INS_PROVISION_ATTESTATION_KEY_CMD = INS_KEYMINT_PROVIDER_APDU_START + 1; //0x01
  private static final byte INS_PROVISION_ATTESTATION_CERT_DATA_CMD = INS_KEYMINT_PROVIDER_APDU_START + 2; //0x02
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 3;
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 4;
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 5;
  private static final byte INS_LOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 6;
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 7;
  private static final byte INS_SET_VERSION_PATCHLEVEL_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 8; //0x08
  private static final byte INS_SET_BOOT_ENDED_CMD = INS_KEYMINT_PROVIDER_APDU_START + 9; //0x09
  private static final byte INS_PROVISION_DEVICE_UNIQUE_KEY_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 10;
  private static final byte INS_PROVISION_ADDITIONAL_CERT_CHAIN_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 11;

  public static final byte BOOT_KEY_MAX_SIZE = 32;
  public static final byte BOOT_HASH_MAX_SIZE = 32;

  // Provision reporting status
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

  public static final short SHARED_SECRET_KEY_SIZE = 32;
  public static final byte KEYMASTER_SPECIFICATION = 0x01;

  private static byte keymasterState = ILLEGAL_STATE;
  private static byte provisionStatus = NOT_PROVISIONED;
  private static byte kmSpecification;
  private static KMSEProvider seProvider;
  private static KMDecoder decoderInst;
  private static KMRepository repositoryInst;
  private static KMKeymasterApplet appletInst;

  KMAndroidSEApplet() {
	seProvider = new KMAndroidSEProvider();
	repositoryInst = new KMRepository(seProvider.isUpgrading());
    decoderInst = new KMDecoder();
    if(kmSpecification == KEYMASTER_SPECIFICATION) {
    	appletInst = new KMKeymasterApplet(seProvider, repositoryInst, decoderInst);
    } else {
    	appletInst = new KMKeymintApplet(seProvider, repositoryInst, decoderInst);
    }
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    // TODO Get the specification correctly.
    byte Li = bArray[bOffset]; // Length of AID
    byte Lc = bArray[(short) (bOffset + Li + 1)]; // Length of ControlInfo
    byte La = bArray[(short) (bOffset + Li + Lc + 2)]; // Length of application data
    if (La != 1) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    kmSpecification = bArray[(short) (bOffset + Li + Lc + 3)];
    new KMAndroidSEApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  @Override
  public void process(APDU apdu) {
    try {
      // If this is select applet apdu which is selecting this applet then return
      if (apdu.isISOInterindustryCLA()) {
        if (selectingApplet()) {
          return;
        }
      }
      short apduIns = validateApdu(apdu);
      if (((KMAndroidSEProvider) seProvider).isPowerReset()) {
    	appletInst.powerReset();
      }

      if (((KMAndroidSEProvider) seProvider).isProvisionLocked()) {
        switch (apduIns) {
          case INS_SET_BOOT_PARAMS_CMD:
            processSetBootParamsCmd(apdu);
            break;
            
          case INS_SET_BOOT_ENDED_CMD:
            //set the flag to mark boot ended
        	  repositoryInst.setBootEndedStatus(true);
        	appletInst.sendError(apdu, KMError.OK);
            break;   

          default:
        	appletInst.process(apdu);
            break;
        }
        return;
      }

      if (apduIns == KMType.INVALID_VALUE) {
        return;
      }
      switch (apduIns) {
      case INS_PROVISION_ATTESTATION_KEY_CMD:
        processProvisionAttestationKey(apdu);
        provisionStatus |= PROVISION_STATUS_ATTESTATION_KEY;
        appletInst.sendError(apdu, KMError.OK);
        break;
      case INS_PROVISION_ATTESTATION_CERT_DATA_CMD:
        processProvisionAttestationCertDataCmd(apdu);
        provisionStatus |= (PROVISION_STATUS_ATTESTATION_CERT_CHAIN |
            PROVISION_STATUS_ATTESTATION_CERT_PARAMS);
        appletInst.sendError(apdu, KMError.OK);
        break;
        case INS_PROVISION_ATTEST_IDS_CMD:
          processProvisionAttestIdsCmd(apdu);
          provisionStatus |= PROVISION_STATUS_ATTEST_IDS;
          appletInst.sendError(apdu, KMError.OK);
          break;

        case INS_PROVISION_PRESHARED_SECRET_CMD:
          processProvisionPreSharedSecretCmd(apdu);
          provisionStatus |= PROVISION_STATUS_PRESHARED_SECRET;
          appletInst.sendError(apdu, KMError.OK);
          break;

        case INS_GET_PROVISION_STATUS_CMD:
          processGetProvisionStatusCmd(apdu);
          break;

        case INS_LOCK_PROVISIONING_CMD:
          processLockProvisioningCmd(apdu);
          break;

        case INS_SET_BOOT_PARAMS_CMD:

          processSetBootParamsCmd(apdu);
          break;

        case INS_PROVISION_DEVICE_UNIQUE_KEY_CMD:
          processProvisionDeviceUniqueKey(apdu);
          break;

        case INS_PROVISION_ADDITIONAL_CERT_CHAIN_CMD:
          processProvisionAdditionalCertChain(apdu);
          break;

        default:
          appletInst.process(apdu);
          break;
      }
    } catch(Exception e) {
    	KMException.reason();
    } finally {
      appletInst.clean();
    }
  }

  private void processProvisionDeviceUniqueKey(APDU apdu) {
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    short arr = KMArray.instance((short) 1);
    short coseKeyExp = KMCoseKey.exp();
    KMArray.add(arr, (short) 0, coseKeyExp); //[ CoseKey ]
    arr = appletInst.receiveIncoming(apdu, arr);
    // Get cose key.
    short coseKey = KMArray.get(arr, (short) 0);
    short pubKeyLen = KMCoseKey.cast(coseKey).getEcdsa256PublicKey(scratchPad, (short) 0);
    short privKeyLen = KMCoseKey.cast(coseKey).getPrivateKey(scratchPad, pubKeyLen);
    //Store the Device unique Key.
    seProvider.createDeviceUniqueKey(false, scratchPad, (short) 0, pubKeyLen, scratchPad,
        pubKeyLen, privKeyLen);
    short bcc = appletInst.generateBcc(false, scratchPad);
    short len = KMKeymasterApplet.encodeToApduBuffer(bcc, scratchPad, (short) 0,
    		appletInst.MAX_COSE_BUF_SIZE);
    ((KMAndroidSEProvider) seProvider).persistBootCertificateChain(scratchPad, (short) 0, len);
    appletInst.sendError(apdu, KMError.OK);
  }

  private void processProvisionAdditionalCertChain(APDU apdu) {
    // Prepare the expression to decode
    short headers = KMCoseHeaders.exp();
    short arrInst = KMArray.instance((short) 4);
    KMArray.add(arrInst, (short) 0, KMByteBlob.exp());
    KMArray.add(arrInst, (short) 1, headers);
    KMArray.add(arrInst, (short) 2, KMByteBlob.exp());
    KMArray.add(arrInst, (short) 3, KMByteBlob.exp());
    short coseSignArr = KMArray.exp(arrInst);
    short map = KMMap.instance((short) 1);
    KMMap.add(map, (short) 0, KMTextString.exp(), coseSignArr);
    // receive incoming data and decode it.
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = repositoryInst.allocReclaimableMemory(bufferLength);
    short index = bufferStartOffset;
    byte[] buffer = repositoryInst.getHeap();
    while (recvLen > 0 && ((short) (index - bufferStartOffset) < bufferLength)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, buffer, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    // decode
    map = decoderInst.decode(map, buffer, bufferStartOffset, bufferLength);
    arrInst = KMMap.getKeyValue(map, (short) 0);
    // Validate Additional certificate chain.
    short leafCoseKey =
    		appletInst.validateCertChain(false, KMCose.COSE_ALG_ES256, KMCose.COSE_ALG_ES256, arrInst,
            srcBuffer, null);
    // Compare the DK_Pub.
    short pubKeyLen = KMCoseKey.cast(leafCoseKey).getEcdsa256PublicKey(srcBuffer, (short) 0);
    KMDeviceUniqueKey uniqueKey = seProvider.getDeviceUniqueKey(false);
    if (uniqueKey == null) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
    short uniqueKeyLen = uniqueKey.getPublicKey(srcBuffer, pubKeyLen);
    if ((pubKeyLen != uniqueKeyLen) ||
        (0 != Util.arrayCompare(srcBuffer, (short) 0, srcBuffer, pubKeyLen, pubKeyLen))) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
    seProvider.persistAdditionalCertChain(buffer, bufferStartOffset, bufferLength);
    //reclaim memory
    repositoryInst.reclaimMemory(bufferLength);
    appletInst.sendError(apdu, KMError.OK);
  }

  private void processProvisionAttestIdsCmd(APDU apdu) {
    short keyparams = KMKeyParameters.exp();
    short cmd = KMArray.instance((short) 1);
    KMArray.add(cmd, (short) 0, keyparams);
    short args = appletInst.receiveIncoming(apdu, cmd);

    short attData = KMArray.get(args, (short) 0);
    // persist attestation Ids - if any is missing then exception occurs
    setAttestationIds(attData);
  }

  public void setAttestationIds(short attIdVals) {
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
  
  private void processProvisionAttestationCertDataCmd(APDU apdu) {
    // TODO Handle this function properly
	appletInst.processAttestationCertDataCmd(apdu);
  }

  private void processProvisionAttestationKey(APDU apdu) {
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT);
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 3);
    KMArray.add(argsProto, (short) 0, keyparams);
    KMArray.add(argsProto, (short) 1, keyFormatPtr);
    KMArray.add(argsProto, (short) 2, blob);

    short args = appletInst.receiveIncoming(apdu, argsProto);
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
    short arrPtr = appletInst.decodeRawECKey(rawBlob);
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
  }  

  private void processProvisionPreSharedSecretCmd(APDU apdu) {
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 1);
    KMArray.add(argsProto, (short) 0, blob);
    short args = appletInst.receiveIncoming(apdu, argsProto);

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

  }

  //This function masks the error code with POWER_RESET_MASK_FLAG
  // in case if card reset event occurred. The clients of the Applet
  // has to extract the power reset status from the error code and
  // process accordingly.
  private short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 4);
    short powerResetStatus = 0;
    if (((KMAndroidSEProvider) seProvider).isPowerReset()) {
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

  private void processGetProvisionStatusCmd(APDU apdu) {
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, KMInteger.uint_16(provisionStatus));
    appletInst.sendOutgoing(apdu, resp);
  }

  private void processSetBootParamsCmd(APDU apdu) {
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

    short args = appletInst.receiveIncoming(apdu, argsProto);

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
    
    appletInst.reboot();
    appletInst.sendError(apdu, KMError.OK);
  }

  private void processLockProvisioningCmd(APDU apdu) {
    ((KMAndroidSEProvider) seProvider).setProvisionLocked(true);
    appletInst.sendError(apdu, KMError.OK);
  }

  @Override
  public void onCleanup() {
  }

  @Override
  public void onConsolidate() {
  }

  @Override
  public void onRestore(Element element) {
    element.initRead();
    provisionStatus = element.readByte();
    keymasterState = element.readByte();
    repositoryInst.onRestore(element);
    seProvider.onRestore(element);
  }

  @Override
  public Element onSave() {
    // SEProvider count
    short primitiveCount = seProvider.getBackupPrimitiveByteCount();
    short objectCount = seProvider.getBackupObjectCount();
    //Repository count
    primitiveCount += repositoryInst.getBackupPrimitiveByteCount();
    objectCount += repositoryInst.getBackupObjectCount();
    //KMKeymasterApplet count
    primitiveCount += computePrimitveDataSize();
    objectCount += computeObjectCount();

    // Create element.
    Element element = UpgradeManager.createElement(Element.TYPE_SIMPLE,
        primitiveCount, objectCount);
    element.write(provisionStatus);
    element.write(keymasterState);
    repositoryInst.onSave(element);
    seProvider.onSave(element);
    return element;
  }

  private short computePrimitveDataSize() {
    // provisionStatus + keymasterState
    return (short) 2;
  }

  private short computeObjectCount() {
    return (short) 0;
  }

  private short validateApdu(APDU apdu) {
    // Read the apdu header and buffer.
    byte[] apduBuffer = apdu.getBuffer();
    byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);

    // Validate APDU Header.
    if ((apduClass != appletInst.CLA_ISO7816_NO_SM_NO_CHAN)) {
      appletInst.sendError(apdu, KMError.UNSUPPORTED_CLA);
      return KMType.INVALID_VALUE;
    }

    if (kmSpecification == KMKeymasterApplet.KEYMASTER_SPECIFICATION &&
        P1P2 != KMKeymasterApplet.KEYMASTER_HAL_VERSION) {
      appletInst.sendError(apdu, KMError.INVALID_P1P2);
      return KMType.INVALID_VALUE;
    }
    // Validate P1P2.
    if (kmSpecification == KMKeymasterApplet.KEYMINT_SPECIFICATION &&
        P1P2 != KMKeymasterApplet.KM_HAL_VERSION) {
      appletInst.sendError(apdu, KMError.INVALID_P1P2);
      return KMType.INVALID_VALUE;
    }
    return apduBuffer[ISO7816.OFFSET_INS];
  }

  @Override
  public void uninstall() {
	appletInst.onUninstall();
  }
  
  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  @Override
  public boolean select() {
	return appletInst.onSelect();
    
  }

  /**
   * De-selects this applet.
   */
  @Override
  public void deselect() {
	appletInst.onDeselect();
  }
}

