package com.duosecurity.duokit.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * A mechanism to compute a message authentication code (MAC) using a combination of a
 * cryptographic hash function of the implementer's choice and a secret cryptographic key.
 */
public interface HMAC {

  /**
   * Compute a RFC 2104-compliant keyed-hash message authentication code.
   *
   * @param key padded to the right with extra zeros to the input block size of the hash
   * function, or the hash of the original key if it's longer than that block size.
   * @param message the message to be authenticated.
   * @throws java.security.NoSuchAlgorithmException if the digest algorithm used (HmacSHA1, SHA1withRSA, etc.)
   * could not be found.
   * @throws java.security.InvalidKeyException if the key provided was not a valid key.
   * @throws java.security.SignatureException if using a {@link java.security.Signature}, and the Signature was
   * not initialized properly.
   */
  public byte[] compute(byte[] key, byte[] message)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
}
