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
package com.android.javacard.kmapplet;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.OnUpgradeListener;
import org.globalplatform.upgrade.UpgradeManager;

import com.android.javacard.kmdevice.KMArray;
import com.android.javacard.kmdevice.KMByteBlob;
import com.android.javacard.kmdevice.KMByteTag;
import com.android.javacard.kmdevice.KMCose;
import com.android.javacard.kmdevice.KMCoseHeaders;
import com.android.javacard.kmdevice.KMCoseKey;
import com.android.javacard.kmdevice.KMDecoder;
import com.android.javacard.kmdevice.KMEnum;
import com.android.javacard.kmdevice.KMEnumArrayTag;
import com.android.javacard.kmdevice.KMEnumTag;
import com.android.javacard.kmdevice.KMInteger;
import com.android.javacard.kmdevice.KMKeyParameters;
import com.android.javacard.kmdevice.KMKeymasterDevice;
import com.android.javacard.kmdevice.KMKeymintDevice;
import com.android.javacard.kmdevice.KMMap;
import com.android.javacard.kmdevice.KMRepository;
import com.android.javacard.kmdevice.KMTag;
import com.android.javacard.kmdevice.KMTextString;
import com.android.javacard.seprovider.KMAndroidSEProvider;
import com.android.javacard.seprovider.KMDeviceUniqueKey;
import com.android.javacard.seprovider.KMError;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMKeymasterProvision;
import com.android.javacard.seprovider.KMKeymintProvision;
import com.android.javacard.seprovider.KMSEProvider;
import com.android.javacard.seprovider.KMType;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.apdu.ExtendedLength;

public class KMAndroidSEApplet extends Applet implements AppletEvent, OnUpgradeListener, ExtendedLength {

  private static final byte KM_BEGIN_STATE = 0x00;
  private static final byte ILLEGAL_STATE = KM_BEGIN_STATE + 1;


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

 // public static final byte BOOT_KEY_MAX_SIZE = 32;
 // public static final byte BOOT_HASH_MAX_SIZE = 32;

  // Provision reporting status


 
  public static final byte KM_40 = 0x00;
  public static final byte KM_41 = 0x01;
  public static final byte KM_100 = 0x03;
  
  private static byte keymasterState = ILLEGAL_STATE;
  //private static byte provisionStatus = NOT_PROVISIONED;
  private static byte kmDevice;
  private static KMSEProvider seProvider;
  private static KMKeymasterProvision seProvisionInst;
  private static KMDecoder decoderInst;
  private static KMRepository repositoryInst;
  private static KMKeymasterDevice kmDeviceInst;

  KMAndroidSEApplet() {
	seProvider = new KMAndroidSEProvider();
	repositoryInst = new KMRepository(seProvider.isUpgrading());
    decoderInst = new KMDecoder();
    if(kmDevice == KM_40 || kmDevice == KM_41) {
    	kmDeviceInst = new KMKeymasterDevice(seProvider, repositoryInst, decoderInst);
    	seProvisionInst = new KMKeymasterProvision(kmDeviceInst, seProvider, decoderInst, repositoryInst);
    } else {
    	kmDeviceInst = new KMKeymintDevice(seProvider, repositoryInst, decoderInst);
    	seProvisionInst = new KMKeymintProvision(kmDeviceInst, seProvider, decoderInst, repositoryInst);
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
    kmDevice = bArray[(short) (bOffset + Li + Lc + 3)];
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
      if (((KMAndroidSEProvider) seProvider).isPowerReset(false)) {
    	kmDeviceInst.powerReset();
      }

      if (((KMAndroidSEProvider) seProvider).isProvisionLocked()) {
        switch (apduIns) {
          case INS_SET_BOOT_PARAMS_CMD:
        	seProvisionInst.processSetBootParamsCmd(apdu);
            break;
            
          case INS_SET_BOOT_ENDED_CMD:
            //set the flag to mark boot ended
        	repositoryInst.setBootEndedStatus(true);
        	kmDeviceInst.sendError(apdu, KMError.OK);
            break;   

          default:
        	kmDeviceInst.process(apdu);
            break;
        }
        return;
      }

      if (apduIns == KMType.INVALID_VALUE) {
        return;
      }
      switch (apduIns) {
        case INS_PROVISION_ATTESTATION_KEY_CMD: // only keymaster
    	  seProvisionInst.processProvisionAttestationKey(apdu);
          break;
        case INS_PROVISION_ATTESTATION_CERT_DATA_CMD: // only keymaster
    	  seProvisionInst.processProvisionAttestationCertDataCmd(apdu);
    	  break;
        case INS_PROVISION_ATTEST_IDS_CMD:
          seProvisionInst.processProvisionAttestIdsCmd(apdu);
          break;

        case INS_PROVISION_PRESHARED_SECRET_CMD:
    	  seProvisionInst.processProvisionPreSharedSecretCmd(apdu);
          break;

        case INS_GET_PROVISION_STATUS_CMD:
          seProvisionInst.processGetProvisionStatusCmd(apdu);
          break;

        case INS_LOCK_PROVISIONING_CMD:
    	  seProvisionInst.processLockProvisioningCmd(apdu);
          break;

        case INS_SET_BOOT_PARAMS_CMD:
          seProvisionInst.processSetBootParamsCmd(apdu);
          break;

        case INS_PROVISION_DEVICE_UNIQUE_KEY_CMD: //only keymint
          seProvisionInst.processProvisionDeviceUniqueKey(apdu);
          break;

        case INS_PROVISION_ADDITIONAL_CERT_CHAIN_CMD:// only keymint
          seProvisionInst.processProvisionAdditionalCertChain(apdu);
          break;

        default:
          kmDeviceInst.process(apdu);
          break;
      }
    } catch (KMException exception) {
      kmDeviceInst.sendError(apdu, KMException.reason());
    } catch (ISOException exp) {
      kmDeviceInst.sendError(apdu, kmDeviceInst.mapISOErrorToKMError(exp.getReason()));
    } catch (CryptoException e) {
      kmDeviceInst.sendError(apdu, kmDeviceInst.mapCryptoErrorToKMError(e.getReason()));
    } catch (Exception e) {
      kmDeviceInst.sendError(apdu, KMError.GENERIC_UNKNOWN_ERROR);
    } finally {
      kmDeviceInst.clean();
    }
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
    keymasterState = element.readByte();
    repositoryInst.onRestore(element);
    seProvider.onRestore(element);
    seProvisionInst.onSave(element);
  }

  @Override
  public Element onSave() {
    // SEProvider count
    short primitiveCount = seProvider.getBackupPrimitiveByteCount();
    short objectCount = seProvider.getBackupObjectCount();
    
    //Provision count
    primitiveCount += seProvisionInst.getBackupPrimitiveByteCount();
    objectCount += seProvisionInst.getBackupObjectCount();
    
    //Repository count
    primitiveCount += repositoryInst.getBackupPrimitiveByteCount();
    objectCount += repositoryInst.getBackupObjectCount();
    //KMKeymasterApplet count
    primitiveCount += computePrimitveDataSize();
    objectCount += computeObjectCount();

    // Create element.
    Element element = UpgradeManager.createElement(Element.TYPE_SIMPLE,
        primitiveCount, objectCount);
    element.write(keymasterState);
    repositoryInst.onSave(element);
    seProvider.onSave(element);
    seProvisionInst.onSave(element);
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
    if ((apduClass != kmDeviceInst.CLA_ISO7816_NO_SM_NO_CHAN)) {
      kmDeviceInst.sendError(apdu, KMError.UNSUPPORTED_CLA);
      return KMType.INVALID_VALUE;
    }

    if (kmDevice == KMKeymasterDevice.KEYMASTER_SPECIFICATION &&
        P1P2 != KMKeymasterDevice.KEYMASTER_HAL_VERSION) {
      kmDeviceInst.sendError(apdu, KMError.INVALID_P1P2);
      return KMType.INVALID_VALUE;
    }
    // Validate P1P2.
    if (kmDevice == KMKeymasterDevice.KEYMINT_SPECIFICATION &&
        P1P2 != KMKeymasterDevice.KM_HAL_VERSION) {
      kmDeviceInst.sendError(apdu, KMError.INVALID_P1P2);
      return KMType.INVALID_VALUE;
    }
    return apduBuffer[ISO7816.OFFSET_INS];
  }

  @Override
  public void uninstall() {
	kmDeviceInst.onUninstall();
  }
  
  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  @Override
  public boolean select() {
	return kmDeviceInst.onSelect();
    
  }

  /**
   * De-selects this applet.
   */
  @Override
  public void deselect() {
	kmDeviceInst.onDeselect();
  }
}

