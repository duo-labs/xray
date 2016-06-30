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

public class XrayKeygenTask extends AsyncTask<Void, Void, Boolean> {
    private final static String SHARED_PREFERENCES_NAME = "Xray";
    private static final String TAG = "XrayKeygenTask";
    private static final String CURVE_NAME = "secp256r1";

    private ECParams ecp;
    private Crypto crypto;

    private SharedPreferences sharedPreferences = null;
    private StringPreference mobilePubKey = null;
    private StringPreference mobilePrivKey = null;

    private TaskListener taskListener;

    public interface TaskListener {
        void onFinished(Boolean result);
    }

    public XrayKeygenTask(Activity activity, TaskListener callback) {
        taskListener = callback;
        sharedPreferences = activity.getSharedPreferences(SHARED_PREFERENCES_NAME, activity.MODE_PRIVATE);
        mobilePubKey = PreferenceProvider.provide_mobile_pubkey(sharedPreferences);
        mobilePrivKey = PreferenceProvider.provide_mobile_privkey(sharedPreferences);
        crypto = Crypto.getInstance();
    }

    @Override
    protected Boolean doInBackground(Void... arg0) {
        try {
            if (mobilePubKey.isSet() && mobilePrivKey.isSet()) {
                return true;
            }

            ecp = ECParams.getParams(CURVE_NAME);
            KeyPair kpA = crypto.generateKeyPairParams(ecp);

            Log.d(TAG, "public: " + crypto.base64Encode(kpA.getPublic().getEncoded()));
            Log.d(TAG, "private: " + crypto.base64Encode(kpA.getPrivate().getEncoded()));

            mobilePrivKey.set(Crypto.base64Encode(kpA.getPrivate().getEncoded()));
            mobilePubKey.set(Crypto.base64Encode(kpA.getPublic().getEncoded()));

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
