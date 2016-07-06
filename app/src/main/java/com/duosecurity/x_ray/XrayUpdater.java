package com.duosecurity.x_ray;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
//import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.util.Log;

public class XrayUpdater {
    private Activity activity = null;
    private Context context = null;

    private final static String TAG = "XrayUpdater";

//    private final static String SHARED_PREFERENCES_NAME = "Xray";

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

//    private SharedPreferences sharedPreferences = null;

    public XrayUpdater(Activity act) {
        activity = act;
        context = activity.getApplicationContext();
//        sharedPreferences = activity.getSharedPreferences(SHARED_PREFERENCES_NAME, activity.MODE_PRIVATE);
    }

    public void startUpdater() {
        if (requestPermissions()) {
            startUpdateTask();
        }
//        // first generate a keypair for verifying authenticity of received manifest/apk file
//        XrayKeygenTask keygenTask = new XrayKeygenTask(sharedPreferences, new XrayKeygenTask.TaskListener() {
//            @Override
//            public void onFinished(Boolean result) {
//                if (result) {
//                    // if keygen succeeded and we have necessary permissions, start update immediately
//                    // otherwise, we'll start the update in the onRequestPermissionsResult callback
//                    if (requestPermissions()) {
//                        startUpdateTask();
//                    }
//                } else {
//                    Log.d(TAG, "Exiting updater");
//                }
//            }
//        });
//        keygenTask.execute();
    }

    private void startUpdateTask() {
        XrayUpdateTask updateTask = new XrayUpdateTask(context);
        updateTask.execute();
    }

    private boolean requestPermissions() {
        // TODO check for new version before requesting permissions
        int permission = ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            Log.d(TAG, "Requesting permissions");
            ActivityCompat.requestPermissions(
                    activity,
                    PERMISSIONS_STORAGE,
                    REQUEST_EXTERNAL_STORAGE
            );
            return false; // requesting permissions asynchronously. we'll get the result in onRequestPermissionsResult
        }
        return true; // already have permissions
    }

    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        if (requestCode == REQUEST_EXTERNAL_STORAGE && grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            // user gave us permission to write to external storage, so kick off update task
            startUpdateTask();
        } else {
            Log.d(TAG, "Update request denied by user");
        }
    }
}
