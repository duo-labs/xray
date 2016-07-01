package com.duosecurity.x_ray;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.util.Log;

import com.duosecurity.duokit.crypto.Crypto;
import com.duosecurity.duokit.crypto.ECParams;
import com.duosecurity.x_ray.preferences.StringPreference;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class XrayKeygenTask extends AsyncTask<Void, Void, Boolean> {

    private static final String TAG = "XrayKeygenTask";
    private static final String CURVE_NAME = "secp256r1";

    private ECParams ecp;
    private Crypto crypto;

    private SharedPreferences sharedPreferences = null;
    private TaskListener taskListener;

    private final static String SERVER_PUB_KEY =
        "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD/////////////" +
        "//8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvO" +
        "PD4n0mBLBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7L" +
        "tkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABE2Qsg162yB51BbjRHv/PZm+" +
        "AaUU2q//+Nof1cF99aBTbiEVUFihSoPDlH1xTRDFBKaZCEshxRDm4ioP8aTnYAc=";

    public interface TaskListener {
        void onFinished(Boolean result);
    }

    public XrayKeygenTask(SharedPreferences preferences, TaskListener callback) {
        taskListener = callback;
        sharedPreferences = preferences;
        crypto = Crypto.getInstance();
    }

    @Override
    protected Boolean doInBackground(Void... arg0) {
        try {
            StringPreference mobilePubKeyPref = PreferenceProvider.provide_mobile_pubkey(sharedPreferences);
            StringPreference mobilePrivKeyPref = PreferenceProvider.provide_mobile_privkey(sharedPreferences);
            StringPreference sharedSecretPref = PreferenceProvider.provide_shared_secret(sharedPreferences);

            if (mobilePubKeyPref.isSet() && mobilePrivKeyPref.isSet() && sharedSecretPref.isSet()) {
                return true;
            }

            ecp = ECParams.getParams(CURVE_NAME);
            KeyPair kpA = crypto.generateKeyPairParams(ecp);

            mobilePrivKeyPref.set(Crypto.base64Encode(kpA.getPrivate().getEncoded()));
            mobilePubKeyPref.set(Crypto.base64Encode(kpA.getPublic().getEncoded()));

            PublicKey extPubKey = crypto.readPublicKey(SERVER_PUB_KEY);
            PrivateKey mobilePrivKey = crypto.readPrivateKey(mobilePrivKeyPref.get());

            byte[] secret = crypto.ecdh(mobilePrivKey, extPubKey);
            sharedSecretPref.set(Crypto.base64Encode(secret));

            return true;
        } catch (Exception e) {
            Log.d(TAG, "Error generating mobile keypair: " + e.getMessage());
            return false;
        }
    }

    @Override
    protected void onPostExecute(Boolean result) {
        taskListener.onFinished(result);
    }
}
