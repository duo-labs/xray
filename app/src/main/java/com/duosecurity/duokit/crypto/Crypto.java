package com.duosecurity.duokit.crypto;

import android.util.Log;

import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {

    private static final String TAG = Crypto.class.getSimpleName();

    private static final String PROVIDER = "SC";

    private static final String KEGEN_ALG = "ECDH";

    private static Crypto instance;

    static {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }

    private KeyFactory kf;
    private KeyPairGenerator kpg;

    public static synchronized Crypto getInstance() {
        if (instance == null) {
            instance = new Crypto();
        }

        return instance;
    }

    private Crypto() {
        try {
            kf = KeyFactory.getInstance(KEGEN_ALG, PROVIDER);
            kpg = KeyPairGenerator.getInstance(KEGEN_ALG, PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public synchronized KeyPair generateKeyPairParams(ECParams ecp) throws Exception {
        EllipticCurve curve = toCurve(ecp);
        ECParameterSpec esSpec = new ECParameterSpec(curve, ecp.getG(), ecp.getN(), ecp.h);

        kpg.initialize(esSpec);

        return kpg.generateKeyPair();
    }

    public synchronized KeyPair generateKeyPairNamedCurve(String curveName) throws Exception {
        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec(curveName);
        kpg.initialize(ecParamSpec);

        return kpg.generateKeyPair();
    }

    public static String base64Encode(byte[] b) {
        try {
            return new String(Base64.encode(b), "ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String hex(byte[] bytes) {
        try {
            return new String(Hex.encode(bytes), "ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] base64Decode(String str) {
        return Base64.decode(str);
    }

    public static EllipticCurve toCurve(ECParams ecp) {
        ECFieldFp fp = new ECFieldFp(ecp.getP());

        return new EllipticCurve(fp, ecp.getA(), ecp.getB());
    }

    public byte[] ecdh(PrivateKey myPrivKey, PublicKey otherPubKey) throws Exception {
        ECPublicKey ecPubKey = (ECPublicKey) otherPubKey;
        Log.d(TAG, "other public key:" + otherPubKey.toString());
        Log.d(TAG, "public key Wx: "
                + ecPubKey.getW().getAffineX().toString(16));
        Log.d(TAG, "public key Wy: "
                + ecPubKey.getW().getAffineY().toString(16));

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", PROVIDER);
        keyAgreement.init(myPrivKey);
        keyAgreement.doPhase(otherPubKey, true);

        return keyAgreement.generateSecret();
    }

    public synchronized PublicKey readPublicKey(String keyStr) throws Exception {
        X509EncodedKeySpec x509ks = new X509EncodedKeySpec(
                Base64.decode(keyStr));
        return kf.generatePublic(x509ks);
    }

    public synchronized PrivateKey readPrivateKey(String keyStr) throws Exception {
        PKCS8EncodedKeySpec p8ks = new PKCS8EncodedKeySpec(
                Base64.decode(keyStr));

        return kf.generatePrivate(p8ks);
    }

    public synchronized KeyPair readKeyPair(String pubKeyStr, String privKeyStr)
            throws Exception {
        return new KeyPair(readPublicKey(pubKeyStr), readPrivateKey(privKeyStr));
    }

    public static String AESEncrypt(byte[] secret, byte[] input) {
        byte[] output = null;
        try {
            SecretKeySpec keySpec = null;
            keySpec = new SecretKeySpec(secret, "AES");
            // we are only encrypting one block so ECB is actually ok,
            // and what the other side expects
            Cipher cipher = Cipher.getInstance("AES");
            //Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            output = cipher.doFinal(input);
        } catch (Exception e) {
            Log.d(TAG, "AES encrypt error: " + e.getMessage());
        }

        return Crypto.base64Encode(output);
    }
}
