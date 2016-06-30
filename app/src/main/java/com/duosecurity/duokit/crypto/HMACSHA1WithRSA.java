package com.duosecurity.duokit.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import org.spongycastle.openssl.PEMReader;

public class HMACSHA1WithRSA implements HMAC {

  /** Compute a RFC 2104-compliant HMAC using the SHA-1 with RSA cryptographic hash function. */
  @Override public byte[] compute(byte[] key, byte[] message)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Reader reader = new InputStreamReader(new ByteArrayInputStream(key));
    PEMReader pem = new PEMReader(reader);
    KeyPair kp = null;
    try {
      kp = (KeyPair) pem.readObject();
      pem.close();
    } catch (IOException e) {
      throw new InvalidKeyException(e.getCause());
    }
    PrivateKey privkey = kp.getPrivate();

    Signature instance = null;
    try {
      instance = Signature.getInstance("SHA1withRSA");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA1withRSA algorithm not found");
    }

    instance.initSign(privkey);
    instance.update(message);
    return instance.sign();
  }
}
