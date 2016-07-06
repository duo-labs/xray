package com.duosecurity.x_ray;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.util.Log;

public class XrayUpdater {
    private Activity activity = null;
    private Context context = null;

    private final static String TAG = XrayUpdater.class.getSimpleName();

    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    public static final int REQUEST_EXTERNAL_STORAGE = 1;

    public XrayUpdater(Activity act) {
        activity = act;
        context = activity.getApplicationContext();
    }

    public void startUpdater() {
        if (requestPermissions()) {
            startUpdateTask();
        }
    }

    private void startUpdateTask() {
        XrayUpdateTask updateTask = new XrayUpdateTask(context);
        updateTask.execute();
    }

    private boolean requestPermissions() {
        // TODO check for new version before requesting permissions
        int permission = ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        if (permission != PackageManager.PERMISSION_GRANTED) {
            new AlertDialog.Builder(activity)
                .setTitle("Update Available")
                .setMessage("A new version of X-Ray is available. Would you like to download it now? (Requires permissions to write to storage)")
                .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.d(TAG, "Requesting permissions");
                        ActivityCompat.requestPermissions(
                            activity,
                            PERMISSIONS_STORAGE,
                            REQUEST_EXTERNAL_STORAGE
                        );
                    }
                })
                .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.d(TAG, "Update request denied by user");
                    }
                })
                .show();
            return false; // don't have permissions yet (either already denied, or waiting for user to approve)
        }
        return true; // already have permissions
    }

    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            // user gave us permission to write to external storage, so kick off update task
            startUpdateTask();
        } else {
            Log.d(TAG, "Update request denied by user");
        }
    }
}
