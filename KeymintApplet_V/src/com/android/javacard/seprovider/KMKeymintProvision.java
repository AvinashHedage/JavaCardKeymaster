package com.android.javacard.seprovider;

import com.android.javacard.kmdevice.KMArray;
import com.android.javacard.kmdevice.KMByteBlob;
import com.android.javacard.kmdevice.KMCose;
import com.android.javacard.kmdevice.KMCoseHeaders;
import com.android.javacard.kmdevice.KMCoseKey;
import com.android.javacard.kmdevice.KMDecoder;
import com.android.javacard.kmdevice.KMInteger;
import com.android.javacard.kmdevice.KMKeymasterDevice;
import com.android.javacard.kmdevice.KMMap;
import com.android.javacard.kmdevice.KMRepository;
import com.android.javacard.kmdevice.KMTextString;

import javacard.framework.APDU;
import javacard.framework.Util;

public class KMKeymintProvision extends KMKeymasterProvision{

  public KMKeymintProvision(KMKeymasterDevice deviceInst, KMSEProvider provider,  KMDecoder decoder, KMRepository repoInst){
	super(deviceInst, provider, decoder, repoInst);
  }
  
  @Override
  public void processProvisionAttestationKey(APDU apdu) {
    kmDeviceInst.sendError(apdu, KMError.CMD_NOT_ALLOWED);
  }

  @Override
  public void processProvisionAttestationCertDataCmd(APDU apdu) {
	kmDeviceInst.sendError(apdu, KMError.CMD_NOT_ALLOWED); 
  }
  
  @Override  
  public void processProvisionDeviceUniqueKey(APDU apdu) {
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    short arr = KMArray.instance((short) 1);
    short coseKeyExp = KMCoseKey.exp();
    KMArray.add(arr, (short) 0, coseKeyExp); //[ CoseKey ]
    arr = kmDeviceInst.receiveIncoming(apdu, arr);
    // Get cose key.
    short coseKey = KMArray.get(arr, (short) 0);
    short pubKeyLen = KMCoseKey.cast(coseKey).getEcdsa256PublicKey(scratchPad, (short) 0);
    short privKeyLen = KMCoseKey.cast(coseKey).getPrivateKey(scratchPad, pubKeyLen);
    //Store the Device unique Key.
    seProvider.createDeviceUniqueKey(false, scratchPad, (short) 0, pubKeyLen, scratchPad,
        pubKeyLen, privKeyLen);
    short bcc = kmDeviceInst.generateBcc(false, scratchPad);
    short len = KMKeymasterDevice.encodeToApduBuffer(bcc, scratchPad, (short) 0,
    		kmDeviceInst.MAX_COSE_BUF_SIZE);
    ((KMAndroidSEProvider) seProvider).persistBootCertificateChain(scratchPad, (short) 0, len);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  @Override
  public void processProvisionAdditionalCertChain(APDU apdu) {
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
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = kmRepositroyInst.allocReclaimableMemory(bufferLength);
    byte[] buffer = kmRepositroyInst.getHeap();
    map = kmDeviceInst.receiveIncoming(apdu, map, buffer, bufferLength, bufferStartOffset);
    arrInst = KMMap.getKeyValue(map, (short) 0);
    // Validate Additional certificate chain.
    short leafCoseKey =
    		kmDeviceInst.validateCertChain(false, KMCose.COSE_ALG_ES256, KMCose.COSE_ALG_ES256, arrInst,
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
    kmRepositroyInst.reclaimMemory(bufferLength);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }
  
  @Override
  public short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 2);

    Util.setShort(KMInteger.getBuffer(int32Ptr),
        (short) (KMInteger.getStartOff(int32Ptr)),
        err);

    return int32Ptr;
  }
  
}
