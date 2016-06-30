package com.duosecurity.duokit.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HMACSHA1 implements HMAC {

  /** Compute a RFC 2104-compliant HMAC using the SHA-1 cryptographic hash function. */
  @Override public byte[] compute(byte[] key, byte[] message)
      throws NoSuchAlgorithmException, InvalidKeyException {
    SecretKey secretKey = null;
    secretKey = new SecretKeySpec(key, "RAW");
    Mac mac = null;
    try {
      mac = Mac.getInstance("HmacSHA1");
    } catch (NoSuchAlgorithmException e) {
      mac = Mac.getInstance("HMAC-SHA-1");
    }
    mac.init(secretKey);
    return mac.doFinal(message);
  }
}
