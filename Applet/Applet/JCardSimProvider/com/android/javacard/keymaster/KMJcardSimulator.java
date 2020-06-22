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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simulator only supports 512 bit RSA key pair, 128 AES Key, 128 bit 3Des key, less then 256 bit EC
 * Key, and upto 512 bit HMAC key. Also simulator does not support TRNG, so this implementation just
 * creates its own RNG using PRNG.
 */
public class KMJcardSimulator implements KMCryptoProvider {
  public static final short AES_GCM_TAG_LENGTH = 12;
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final short MAX_RND_NUM_SIZE = 64;
  public static final short ENTROPY_POOL_SIZE = 16; // simulator does not support 256 bit aes keys
  public static final byte[] aesICV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  private static final int AES_GCM_KEY_SIZE = 16;
  public static boolean jcardSim = false;
  private static Signature kdf;
  private static Signature hmacSignature;

  private static byte[] rngCounter;
  private static AESKey aesRngKey;
  private static Cipher aesRngCipher;
  private static byte[] entropyPool;
  private static byte[] rndNum;

  // Implements Oracle Simulator based restricted crypto provider
  public KMJcardSimulator() {
    // Various Keys
    kdf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    hmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
    // RNG
    rndNum = JCSystem.makeTransientByteArray(MAX_RND_NUM_SIZE, JCSystem.CLEAR_ON_RESET);
    entropyPool = JCSystem.makeTransientByteArray(ENTROPY_POOL_SIZE, JCSystem.CLEAR_ON_RESET);
    rngCounter = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_RESET);
    initEntropyPool(entropyPool);
    try {
      aesRngCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    } catch (CryptoException exp) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }
    aesRngKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    // various ciphers

  }

  @Override
  public KeyPair createRsaKeyPair() {
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    rsaKeyPair.genKeyPair();
    return rsaKeyPair;
  }

  @Override
  public RSAPrivateKey createRsaKey(byte[] modBuffer, short modOff, short modLength,
                                    byte[] privBuffer, short privOff, short privLength) {
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    RSAPrivateKey privKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
    privKey.setExponent(privBuffer, privOff, privLength);
    privKey.setModulus(modBuffer, modOff, modLength);
    return privKey;

  }

  @Override
  public KeyPair createECKeyPair() {
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ecKeyPair.genKeyPair();
    return ecKeyPair;
  }

  @Override
  public ECPrivateKey createEcKey(byte[] privBuffer, short privOff, short privLength) {
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    privKey.setS(privBuffer,privOff, privLength);
    return privKey;
  }

  @Override
  public AESKey createAESKey(short keysize) {
    byte[] rndNum = new byte[(short) (keysize/8)];
    return createAESKey(rndNum, (short)0, (short)rndNum.length);
  }

  @Override
  public AESKey createAESKey(byte[] buf, short startOff, short length) {
    AESKey key = null;
    short keysize = (short)(length * 8);
    if (keysize == 128) {
      key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
      key.setKey(buf, (short) startOff);
    }else if (keysize == 256){
      key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
      key.setKey(buf, (short) startOff);
    }
 //   byte[] buffer = new byte[length];
 //   Util.arrayCopyNonAtomic(buf, startOff, buffer, (short)0,length);
 //   print("AES Key", buffer);
    return key;
  }

  @Override
  public DESKey createTDESKey() {
    // TODO check whether 168 bit or 192 bit
    byte[] rndNum = new byte[24];
    newRandomNumber(rndNum, (short) 0, (short)rndNum.length);
    return createTDESKey(rndNum, (short)0, (short)rndNum.length);
  }

  @Override
  public DESKey createTDESKey(byte[] secretBuffer, short secretOff, short secretLength) {
    DESKey triDesKey =
      (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
    triDesKey.setKey(secretBuffer, secretOff);
    return triDesKey;
  }

  @Override
  public HMACKey createHMACKey(short keysize) {
    if((keysize % 8 != 0) || !(keysize >= 64 && keysize <= 512)){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] rndNum = new byte[(short) (keysize/8)];
    newRandomNumber(rndNum, (short) 0, (short)(keysize/8));
    return createHMACKey(rndNum, (short)0, (short)rndNum.length);
  }

  @Override
  public HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength) {
    HMACKey key = null;
    key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
      KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
    key.setKey(secretBuffer,secretOff,secretLength);
    return key;
  }

  @Override
  public short aesGCMEncrypt(
      AESKey key,
      byte[] secret,
      short secretStart,
      short secretLen,
      byte[] encSecret,
      short encSecretStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte[] authTag,
      short authTagStart,
      short authTagLen) {
    //Create the sun jce compliant aes key
    byte[] keyMaterial = new byte[16];
    if(key.getSize() == 128){
      keyMaterial = new byte[16];
    }else if(key.getSize() == 256){
      keyMaterial = new byte[32];
    }
    key.getKey(keyMaterial,(short)0);
    //print("KeyMaterial Enc", keyMaterial);
    //print("Authdata Enc", authData, authDataStart, authDataLen);
    java.security.Key aesKey = new SecretKeySpec(keyMaterial,(short)0,(short)16, "AES");
    // Create the cipher
    javax.crypto.Cipher cipher = null;
    try {
      cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    if(nonceLen != AES_GCM_NONCE_LENGTH){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    Util.arrayCopyNonAtomic(nonce,nonceStart,iv,(short)0,AES_GCM_NONCE_LENGTH);
    // Init Cipher
    GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, nonce,nonceStart,AES_GCM_NONCE_LENGTH);
    try {
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    // Create auth data
    byte[] aad = new byte[authDataLen];
    Util.arrayCopyNonAtomic(authData,authDataStart,aad,(short)0,authDataLen);
   // print("AAD", aad);
    cipher.updateAAD(aad);
    // Encrypt secret
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize(secretLen)];
    try {
      len =  (short)(cipher.doFinal(secret,secretStart,secretLen,outputBuf,(short)0));
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Extract Tag appended at the end.
    Util.arrayCopyNonAtomic(outputBuf, (short)(len - AES_GCM_TAG_LENGTH),authTag,authTagStart,AES_GCM_TAG_LENGTH);
    //Copy the encrypted data
    Util.arrayCopyNonAtomic(outputBuf, (short)0,encSecret,encSecretStart,(short)(len - AES_GCM_TAG_LENGTH));
    return (short)(len - AES_GCM_TAG_LENGTH);
  }

/*
    // Decrypt; nonce is shared implicitly
    cipher.init(Cipher.DECRYPT_MODE, key, spec);

    // EXPECTED: Uncommenting this will cause an AEADBadTagException when decrypting
    // because AAD value is altered
    if (testNum == 1) aad[1]++;

    cipher.updateAAD(aad);

    // EXPECTED: Uncommenting this will cause an AEADBadTagException when decrypting
    // because the encrypted data has been altered
    if (testNum == 2) cipherText[10]++;

    // EXPECTED: Uncommenting this will cause an AEADBadTagException when decrypting
    // because the tag has been altered
    if (testNum == 3) cipherText[cipherText.length - 2]++;

    try {
      byte[] plainText = cipher.doFinal(cipherText);
      if (testNum != 0) {
        System.out.println("Test Failed: expected AEADBadTagException not thrown");
      } else {
        // check if the decryption result matches
        if (Arrays.equals(input, plainText)) {
          System.out.println("Test Passed: match!");
        } else {
          System.out.println("Test Failed: result mismatch!");
          System.out.println(new String(plainText));
        }
      }
    } catch(AEADBadTagException ex) {
      if (testNum == 0) {
        System.out.println("Test Failed: unexpected ex " + ex);
        ex.printStackTrace();
      } else {
        System.out.println("Test Passed: expected ex " + ex);
      }
    }
  }
  }*/

  public boolean aesGCMDecrypt(
      AESKey key,
      byte[] encSecret,
      short encSecretStart,
      short encSecretLen,
      byte[] secret,
      short secretStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte[] authTag,
      short authTagStart,
      short authTagLen) {
  //Create the sun jce compliant aes key
    byte[] keyMaterial = new byte[16];
    if(key.getSize() == 128){
      keyMaterial = new byte[16];
    }else if(key.getSize() == 256){
      keyMaterial = new byte[32];
    }
    key.getKey(keyMaterial,(short)0);
    //print("KeyMaterial Dec", keyMaterial);
    //print("Authdata Dec", authData, authDataStart, authDataLen);

    java.security.Key aesKey = new SecretKeySpec(keyMaterial,(short)0,(short)16, "AES");
    // Create the cipher
  javax.crypto.Cipher cipher = null;
  try {
  cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
  } catch (NoSuchAlgorithmException e) {
  e.printStackTrace();
  CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
  } catch (NoSuchProviderException e) {
  e.printStackTrace();
  CryptoException.throwIt(CryptoException.INVALID_INIT);
  } catch (NoSuchPaddingException e) {
  e.printStackTrace();
  CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
  }
  // Copy nonce
  if(nonceLen != AES_GCM_NONCE_LENGTH){
  CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
  }
  byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
  Util.arrayCopyNonAtomic(nonce,nonceStart,iv,(short)0,AES_GCM_NONCE_LENGTH);
  // Init Cipher
  GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, nonce,nonceStart,AES_GCM_NONCE_LENGTH);
  try {
  cipher.init(javax.crypto.Cipher.DECRYPT_MODE, aesKey, spec);
  } catch (InvalidKeyException e) {
  e.printStackTrace();
  CryptoException.throwIt(CryptoException.INVALID_INIT);
  } catch (InvalidAlgorithmParameterException e) {
  e.printStackTrace();
  CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
  }
  // Create auth data
  byte[] aad = new byte[authDataLen];
  Util.arrayCopyNonAtomic(authData,authDataStart,aad,(short)0,authDataLen);
  cipher.updateAAD(aad);
  // Append the auth tag at the end of data
    byte[] inputBuf = new byte[(short)(encSecretLen + AES_GCM_TAG_LENGTH)];
    Util.arrayCopyNonAtomic(encSecret,encSecretStart,inputBuf,(short)0,encSecretLen);
    Util.arrayCopyNonAtomic(authTag,authTagStart,inputBuf,encSecretLen,AES_GCM_TAG_LENGTH);
  // Decrypt
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize((short)inputBuf.length)];
    try {
      len =  (short)(cipher.doFinal(inputBuf,(short)0,(short)inputBuf.length,outputBuf,(short)0));
    }catch(AEADBadTagException e){
      e.printStackTrace();
      return false;
    }catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    //Copy the decrypted data
    Util.arrayCopyNonAtomic(outputBuf, (short)0,secret,secretStart,len);
    return true;
  }

  @Override
  public byte[] getTrueRandomNumber(short i) {
    // ignore the size as simulator only supports 128 bit entropy
    return entropyPool;
  }

  @Override
  public short aesCCMSign(
      byte[] bufIn,
      short bufInStart,
      short buffInLength,
      byte[] masterKeySecret,
      byte[] bufOut,
      short bufStart) {
    if (masterKeySecret.length > 16) {
      return -1;
    }

    AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    key.setKey(masterKeySecret, (short) 0);
    byte[] in = new byte[buffInLength];
    Util.arrayCopyNonAtomic(bufIn, bufInStart,in,(short)0,buffInLength);
    kdf.init(key, Signature.MODE_SIGN);
    short len = kdf.sign(bufIn, bufInStart, buffInLength, bufOut, bufStart);
    byte[] out = new byte[len];
    Util.arrayCopyNonAtomic(bufOut, bufStart,out,(short)0,len);
    return len;
  }


  @Override
  public HMACKey cmacKdf(byte[] keyMaterial, byte[] label, byte[] context, short contextStart, short contextLength) {
    // This is hardcoded to requirement - 32 byte output with two concatenated 16 bytes K1 and K2.
    final byte n = 2; // hardcoded - L is 32 bytes and h is 16 byte i.e. CMAC output of AES 128 bit key.
    final byte[] L = {0,0,1,0}; // [L] 256 bits - hardcoded 32 bits as per reference impl in keymaster.
    final byte[] zero = {0}; //
    byte[] iBuf = new byte[]{0,0,0,0}; // [i] counter - 32 bits
    byte[] keyOut = new byte[(short)(n*16)];
    Signature prf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    key.setKey(keyMaterial, (short) 0);
    prf.init(key, Signature.MODE_SIGN);
    byte i =1;
    short pos = 0;
    while (i <= n) {
      iBuf[3] = i;
      prf.update(iBuf, (short) 0, (short) 4); // 4 bytes of iBuf with counter in it
      prf.update(label, (short) 0, (short) label.length); // label
      prf.update(zero, (short) 0, (short) 1); // 1 byte of 0x00
      prf.update(context, contextLength, contextLength); // context
      pos = prf.sign(L, (short) 0, (short) 4, keyOut, pos); // 4 bytes of L - signature of 16 bytes
      i++;
    }
    return createHMACKey(keyOut, (short)0, (short)keyOut.length);
  }

  @Override
  public short hmacSign(HMACKey key, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart) {
    hmacSignature.init(key, Signature.MODE_SIGN);
    return hmacSignature.sign(data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public boolean hmacVerify(HMACKey key, byte[] data, short dataStart, short dataLength,
                          byte[] mac, short macStart, short macLength) {
    hmacSignature.init(key, Signature.MODE_VERIFY);
    return hmacSignature.verify(data, dataStart, dataLength, mac, macStart, macLength);
  }

  @Override
  public KMCipher createRsaDecipher(short padding, byte[] secret, short secretStart,
                                    short secretLength, byte[] modBuffer, short modOff, short modLength) {
    byte cipherAlg = Cipher.ALG_RSA_NOPAD;
    //TODO implement OAEP algorithm using SunJCE.
    if(padding == KMCipher.PAD_PKCS1_OAEP_SHA256) CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    else if(padding == KMCipher.PAD_PKCS1) cipherAlg = Cipher.ALG_RSA_PKCS1;
    else cipherAlg = Cipher.ALG_RSA_NOPAD;
    Cipher rsaCipher = Cipher.getInstance(cipherAlg,false);
    RSAPrivateKey key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
    key.setExponent(secret,secretStart,secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaCipher.init(key,Cipher.MODE_DECRYPT);
    KMCipherImpl inst = new KMCipherImpl(rsaCipher);
    inst.setCipherAlgorithm(cipherAlg);
    inst.setMode(Cipher.MODE_DECRYPT);
    inst.setPaddingAlgorithm(padding);
    return inst;
  }

  @Override
  public Signature createRsaSigner(short msgDigestAlg, short padding, byte[] secret, short secretStart, short secretLength, byte[] modBuffer, short modOff, short modLength) {
    short alg = Signature.ALG_RSA_SHA_256_PKCS1;
    if(msgDigestAlg == MessageDigest.ALG_NULL) CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    else if(padding == KMCipher.PAD_NOPAD) CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    else if(padding == KMCipher.PAD_PKCS1_PSS) alg = Signature.ALG_RSA_SHA_256_PKCS1_PSS;
    else if(padding == KMCipher.PAD_PKCS1) alg = Signature.ALG_RSA_SHA_256_PKCS1;
    else CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    Signature rsaSigner = Signature.getInstance((byte)alg, false);
    RSAPrivateKey key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
    key.setExponent(secret,secretStart,secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaSigner.init(key,Signature.MODE_SIGN);
    return rsaSigner;
  }

  @Override
  public Signature createEcSigner(short msgDigestAlg, byte[] secret, short secretStart, short secretLength) {
    short alg = Signature.ALG_ECDSA_SHA_256;
    if(msgDigestAlg == MessageDigest.ALG_NULL) CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    //KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    //ecKeyPair.genKeyPair();
    //ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    //privKey.setS(secret,secretStart, secretLength);
    ECPrivateKey key = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    key.setS(secret,secretStart,secretLength);
    Signature ecSigner = Signature.getInstance((byte)alg,false);
    ecSigner.init(key,Signature.MODE_SIGN);
    return ecSigner;
  }

  @Override
  public KMCipher createSymmetricCipher(
      short cipherAlg,  short mode, short padding, byte[] secret, short secretStart, short secretLength) {
    return createSymmetricCipher(cipherAlg, mode, padding, secret,secretStart,secretLength,null,(short)0,(short)0);
  }

  @Override
  public KMCipher createSymmetricCipher(short cipherAlg, short mode, short padding, byte[] secret,
                                        short secretStart, short secretLength,
                                        byte[] ivBuffer, short ivStart, short ivLength) {
    Key key = null;
    Cipher symmCipher = null;
    short len = 0;
    switch (secretLength){
      case 32:
        len = KeyBuilder.LENGTH_AES_256;
        break;
      case 16:
        len = KeyBuilder.LENGTH_AES_128;
        break;
      case 24:
        len = KeyBuilder.LENGTH_DES3_3KEY;
        break;
      default:
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        break;
    }
    switch(cipherAlg){
      case KMCipher.ALG_AES_BLOCK_128_CBC_NOPAD:
        cipherAlg = Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
        key = KeyBuilder.buildKey(KeyBuilder.TYPE_AES,len,false);
        ((AESKey) key).setKey(secret,secretStart);
        symmCipher = Cipher.getInstance((byte)cipherAlg, false);
        symmCipher.init(key, (byte) mode, ivBuffer, ivStart, ivLength);
        break;
      case KMCipher.ALG_AES_BLOCK_128_ECB_NOPAD:
        cipherAlg = Cipher.ALG_AES_BLOCK_128_ECB_NOPAD;
        key = KeyBuilder.buildKey(KeyBuilder.TYPE_AES,len,false);
        ((AESKey) key).setKey(secret,secretStart);
        symmCipher = Cipher.getInstance((byte)cipherAlg, false);
        symmCipher.init(key, (byte) mode);
        break;
      case KMCipher.ALG_DES_CBC_NOPAD:
        cipherAlg = Cipher.ALG_DES_CBC_NOPAD;
        key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,len,false);
        ((DESKey) key).setKey(secret,secretStart);
        symmCipher = Cipher.getInstance((byte)cipherAlg, false);
        symmCipher.init(key, (byte) mode, ivBuffer, ivStart, ivLength);
        break;
      case KMCipher.ALG_DES_ECB_NOPAD:
        cipherAlg = Cipher.ALG_DES_ECB_NOPAD;
        key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,len,false);
        ((DESKey) key).setKey(secret,secretStart);
        symmCipher = Cipher.getInstance((byte)cipherAlg, false);
        symmCipher.init(key, (byte) mode);
        break;
      default://This should never happen
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    KMCipherImpl cipher = new KMCipherImpl(symmCipher);
    cipher.setCipherAlgorithm(cipherAlg);
    cipher.setPaddingAlgorithm(padding);
    cipher.setMode(mode);
    return cipher;
  }

  @Override
  public Signature createHmacSignerVerifier(short purpose, short msgDigestAlg, byte[] secret, short secretStart, short secretLength) {
    short alg = Signature.ALG_HMAC_SHA_256;
    if(msgDigestAlg != MessageDigest.ALG_SHA_256) CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    Signature hmacSignerVerifier = Signature.getInstance((byte)alg,false);
    HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short)(secretLength*8), false);
    key.setKey(secret,secretStart,secretLength);
    hmacSignerVerifier.init(key,(byte)purpose);
    return hmacSignerVerifier;
  }

  @Override
  public KMCipher createAesGcmCipher(short mode, short tagLen, byte[] secret, short secretStart, short secretLength,
                                     byte[] ivBuffer, short ivStart, short ivLength) {
    if(secretLength != 16 && secretLength != 32){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if(ivLength != AES_GCM_NONCE_LENGTH){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if(mode != KMCipher.MODE_ENCRYPT && mode != KMCipher.MODE_DECRYPT){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    //Create the sun jce compliant aes key
    byte[] keyMaterial = new byte[secretLength];
    Util.arrayCopyNonAtomic(secret,secretStart,keyMaterial,(short)0,secretLength);
    //print("KeyMaterial Enc", keyMaterial);
    //print("Authdata Enc", authData, authDataStart, authDataLen);
    java.security.Key aesKey = new SecretKeySpec(keyMaterial,(short)0,keyMaterial.length, "AES");
    // Create the cipher
    javax.crypto.Cipher cipher = null;
    try {
      cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    Util.arrayCopyNonAtomic(ivBuffer,ivStart,iv,(short)0,AES_GCM_NONCE_LENGTH);
    // Init Cipher
    GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv,(short)0,AES_GCM_NONCE_LENGTH);
    try {
      if(mode == KMCipher.MODE_ENCRYPT)mode = javax.crypto.Cipher.ENCRYPT_MODE;
      else mode = javax.crypto.Cipher.DECRYPT_MODE;
      cipher.init(mode, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    KMCipherImpl ret = new KMCipherImpl(cipher);
    ret.setCipherAlgorithm(KMCipher.ALG_AES_GCM);
    ret.setMode(mode);
    ret.setPaddingAlgorithm((short)0);
    return ret;
  }

  @Override
  public void delete(KMCipher cipher) {
    //Don't do anything as we don't pool the objects.
  }

  @Override
  public void delete(Signature signature) {
    //Don't do anything as we don't pool the objects.
  }

  @Override
  public void delete(Key key) {
    // Don't do anything as we don't pool the objects.
  }

  @Override
  public void delete(KeyPair keyPair) {
    // Don't do anything as we don't pool the objects.
  }

  private void initEntropyPool(byte[] pool) {
    byte index = 0;
    RandomData trng;
    while (index < rngCounter.length) {
      rngCounter[index++] = 0;
    }
    try {
      trng = RandomData.getInstance(RandomData.ALG_TRNG);
      trng.nextBytes(pool, (short) 0, (short) pool.length);
    } catch (CryptoException exp) {
      if (exp.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
        // TODO change this when possible
        // simulator does not support TRNG algorithm. So, PRNG algorithm (deprecated) is used.
        trng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        trng.nextBytes(pool, (short) 0, (short) pool.length);
      } else {
        // TODO change this to proper error code
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      }
    }
  }

  // Generate a secure random number from existing entropy pool. This uses aes ecb algorithm with
  // 8 byte rngCounter and 16 byte block size.
  @Override
  public void newRandomNumber(byte[] num, short startOff, short length) {
    KMRepository repository = KMRepository.instance();
    byte[] bufPtr = repository.getHeap();
    short countBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short randBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short len = KMKeymasterApplet.AES_BLOCK_SIZE;
    aesRngKey.setKey(entropyPool, (short) 0);
    aesRngCipher.init(aesRngKey, Cipher.MODE_ENCRYPT, aesICV, (short) 0, (short) 16);
    while (length > 0) {
      if (length < len) len = length;
      // increment rngCounter by one
      incrementCounter();
      // copy the 8 byte rngCounter into the 16 byte rngCounter buffer.
      Util.arrayCopy(rngCounter, (short) 0, bufPtr, countBufInd, (short) rngCounter.length);
      // encrypt the rngCounter buffer with existing entropy which forms the aes key.
      aesRngCipher.doFinal(
          bufPtr, countBufInd, KMKeymasterApplet.AES_BLOCK_SIZE, bufPtr, randBufInd);
      // copy the encrypted rngCounter block to buffer passed in the argument
      Util.arrayCopy(bufPtr, randBufInd, num, startOff, len);
      length = (short) (length - len);
      startOff = (short) (startOff + len);
    }
  }

  // increment 8 byte rngCounter by one
  private void incrementCounter() {
    // start with least significant byte
    short index = (short) (rngCounter.length - 1);
    while (index >= 0) {
      // if the msb of current byte is set then it will be negative
      if (rngCounter[index] < 0) {
        // then increment the rngCounter
        rngCounter[index]++;
        // is the msb still set? i.e. no carry over
        if (rngCounter[index] < 0) break; // then break
        else index--; // else go to the higher order byte
      } else {
        // if msb is not set then increment the rngCounter
        rngCounter[index]++;
        break;
      }
    }
  }

  @Override
  public void addRngEntropy(byte[] num, short offset, short length) {
    // Maximum length can be 256 bytes. But currently we support max 32 bytes seed.
    // Get existing entropy pool.
    if (length > 32) length = 32;
    // Create new temporary pool.
    // Populate the new pool with the entropy which is derived from current entropy pool.
    newRandomNumber(rndNum, (short) 0, (short) entropyPool.length);
    // Copy the entropy to the current pool - updates the entropy pool.
    Util.arrayCopy(rndNum, (short) 0, entropyPool, (short) 0, (short) entropyPool.length);
    short index = 0;
    short randIndex = 0;
    // XOR the seed received from the master in the entropy pool - 16 bytes (entPool.length).
    // at a time.
    while (index < length) {
      entropyPool[randIndex] = (byte) (entropyPool[randIndex] ^ num[(short) (offset + index)]);
      randIndex++;
      index++;
      if (randIndex >= entropyPool.length) {
        randIndex = 0;
      }
    }
  }

  @Override
  public void bypassAesGcm(){
    //ignore
  }

  @Override
  public KMCipher createRsaCipher(short padding, byte[] modBuffer, short modOff, short modLength) {
    byte cipherAlg = Cipher.ALG_RSA_NOPAD;
    //TODO implement OAEP algorithm using SunJCE.
    //TODO for no pad the buffer length must be 255 max.
    if(padding == KMCipher.PAD_PKCS1_OAEP_SHA256) CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    else if(padding == KMCipher.PAD_PKCS1) cipherAlg = Cipher.ALG_RSA_PKCS1;
    else cipherAlg = Cipher.ALG_RSA_NOPAD;
    Cipher rsaCipher = Cipher.getInstance(cipherAlg,false);
    RSAPublicKey key = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
    byte[] exponent = new byte[]{0x01,0x00,0x01};
    key.setExponent(exponent,(short)0,(short)3);
    key.setModulus(modBuffer, modOff, modLength);
    rsaCipher.init(key,Cipher.MODE_ENCRYPT);
    KMCipherImpl inst = new KMCipherImpl(rsaCipher);
    inst.setCipherAlgorithm(cipherAlg);
    inst.setMode(Cipher.MODE_ENCRYPT);
    inst.setPaddingAlgorithm(padding);
    return inst;
  }

  @Override
  public Signature createRsaVerifier(short msgDigestAlg, short padding, byte[] modBuffer, short modOff, short modLength) {
    short alg = Signature.ALG_RSA_SHA_256_PKCS1;
    if(msgDigestAlg == MessageDigest.ALG_NULL) CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    else if(padding == KMCipher.PAD_NOPAD) CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    else if(padding == KMCipher.PAD_PKCS1_PSS) alg = Signature.ALG_RSA_SHA_256_PKCS1_PSS;
    else if(padding == KMCipher.PAD_PKCS1) alg = Signature.ALG_RSA_SHA_256_PKCS1;
    else CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    Signature rsaVerifier = Signature.getInstance((byte)alg, false);
    RSAPublicKey key = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
    byte[] exponent = new byte[]{0x01,0x00,0x01};
    key.setExponent(exponent,(short)0,(short)3);
    key.setModulus(modBuffer, modOff, modLength);
    rsaVerifier.init(key,Signature.MODE_VERIFY);
    return rsaVerifier;
  }
  @Override
  public Signature createEcVerifier(short msgDigestAlg, byte[] pubKey, short pubKeyStart, short pubKeyLength) {
    short alg = Signature.ALG_ECDSA_SHA_256;
    if(msgDigestAlg == MessageDigest.ALG_NULL) CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
//    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
//    ecKeyPair.genKeyPair();
//    ECPublicKey key = (ECPublicKey) ecKeyPair.getPublic();
    ECPublicKey key = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    key.setW(pubKey,pubKeyStart,pubKeyLength);
    Signature ecVerifier = Signature.getInstance((byte)alg,false);
    ecVerifier.init(key,Signature.MODE_VERIFY);
    return ecVerifier;
  }
  /*
  private static void print (String lab, byte[] b, short s, short l){
    byte[] i = new byte[l];
    Util.arrayCopyNonAtomic(b,s,i,(short)0,l);
    print(lab,i);
  }
  private static void print(String label, byte[] buf){
    System.out.println(label+": ");
    StringBuilder sb = new StringBuilder();
    for(int i = 0; i < buf.length; i++){
      sb.append(String.format(" 0x%02X", buf[i])) ;
      if(((i-1)%38 == 0) && ((i-1) >0)){
        sb.append(";\n");
      }
    }
    System.out.println(sb.toString());
  }*/
}
