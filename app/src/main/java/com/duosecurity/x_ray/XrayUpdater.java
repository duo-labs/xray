package com.duosecurity.x_ray;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.util.Log;

import com.duosecurity.x_ray.preferences.StringPreference;

public class XrayUpdater {
    private Activity activity = null;
    private Context context = null;

    private final static String TAG = "XrayUpdater";

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    public XrayUpdater(Activity act) {
        activity = act;
        context = activity.getApplicationContext();

        generateKeyPair();
    }

    private void generateKeyPair() {
        // generate keypair for purposes of verifying authenticity of received manifest/apk file
        XrayKeygenTask keygenTask = new XrayKeygenTask(activity, new XrayKeygenTask.TaskListener() {
            @Override
            public void onFinished(Boolean result) {
                if (result) {
                    checkForUpdates();
                } else {
                    Log.d(TAG, "Exiting updater");
                }
            }
        });
        keygenTask.execute();
    }

    public void startUpdater() {
        XrayUpdateTask updateTask = new XrayUpdateTask(activity);
        updateTask.execute();
    }

    public void checkForUpdates() {
        // TODO check for new version before requesting permissions
        int permission = ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Requesting permissions");
            ActivityCompat.requestPermissions(
                activity,
                PERMISSIONS_STORAGE,
                REQUEST_EXTERNAL_STORAGE
            );
        } else {
            startUpdater();
        }
    }

    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        if (requestCode == REQUEST_EXTERNAL_STORAGE && grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            startUpdater();
        } else {
            Log.d(TAG, "Update request denied by user");
        }
    }
}
