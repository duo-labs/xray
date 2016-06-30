package com.duosecurity.duokit.crypto;

import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.Map;

public class ECParams {

    String name;
    String p;
    String a;
    String b;
    String G;
    String n;
    int h;

    BigInteger pBi;
    ECFieldFp fp;
    EllipticCurve curve;
    BigInteger aBi;
    BigInteger bBi;
    ECPoint ecpG;
    BigInteger nBi;

    ECParams(String name) {
        this.name = name;
    }

    public static final ECParams secp256r1 = new ECParams("secp256r1");

    private static final Map<String, ECParams> PARAMS = new HashMap<String, ECParams>();

    static {
        secp256r1.p = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        secp256r1.a = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
        secp256r1.b = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
        secp256r1.G = "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        secp256r1.n = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
        secp256r1.h = 1;
        secp256r1.init();
        PARAMS.put(secp256r1.name, secp256r1);
    }

    public static ECParams getParams(String name) {
        return PARAMS.get(name);
    }

    private void init() {
        pBi = new BigInteger(p, 16);
        fp = new ECFieldFp(pBi);
        aBi = new BigInteger(a, 16);
        bBi = new BigInteger(b, 16);

        curve = new EllipticCurve(fp, getA(), bBi);

        ecpG = ECPointUtil.decodePoint(curve, Hex.decode(G));

        nBi = new BigInteger(n, 16);
    }

    BigInteger getP() {
        return pBi;
    }

    BigInteger getA() {
        BigInteger positiveA = pBi.add(aBi);
        boolean useA = aBi.abs().equals(aBi);

        return useA ? aBi : positiveA;
    }

    BigInteger getB() {
        return bBi;
    }

    ECFieldFp getField() {
        return fp;
    }

    ECPoint getG() {
        return ecpG;
    }

    BigInteger getN() {
        return nBi;
    }
}
