package com.duosecurity.x_ray;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class XrayUpdater {
    private Activity activity = null;
    private Context context = null;

    private final static String TAG = XrayUpdater.class.getSimpleName();

    private static String[] PERMISSIONS_STORAGE = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
    };

    public static final int REQUEST_EXTERNAL_STORAGE = 1;

    public static final String CHECKSUM_ALGORITHM = "SHA-256";
    public static final String ECDSA_ALGORITHM = "SHA256withECDSA";
    public static final String ECDSA_PROVIDER = "SC"; // spongycastle

    public static final int CONNECTION_TIMEOUT = 15000;
    public static final int READ_TIMEOUT = 15000;

    public final static String DOWNLOAD_URL = "https://labs.duo.com/xray/dl";
    public final static String VERSION_URL = "https://labs.duo.com/xray/version";

    public final static String DOWNLOAD_DIR = "/Download/";
    public final static String FILE_TYPE = "application/vnd.android.package-archive";

    public static final String SERVER_PUB_KEY =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy5bOzkZ36VV+kjSYso0HTCZwHWMT\n" +
        "29lQWpJYAiudtZ65mdcBCgmsB/jAwLIJl8BricbLhGU9FA/Wxha5b3ee7A==";

    private static final String SHARED_PREFERENCES = "X-Ray";
    private static SharedPreferences sharedPreferences = null;

    public XrayUpdater(Activity act) {
        activity = act;
        context = activity.getApplicationContext();
        sharedPreferences = activity.getSharedPreferences(SHARED_PREFERENCES, context.MODE_PRIVATE);
    }

    private void startUpdateTask() {
        XrayUpdateTask updateTask = new XrayUpdateTask(context);
        updateTask.execute();
    }

    public static void setSharedPreference(String preference, String value) {
        sharedPreferences.edit().putString(preference, value).commit();
    }

    public static String getSharedPreference(String preference) {
        return sharedPreferences.getString(preference, "");
    }

    public void checkForUpdates() {
        Log.d(TAG, "Checking for updates...");

        XrayCheckTask checkTask = new XrayCheckTask(new XrayCheckTask.TaskListener() {
            @Override
            public void onFinished(Boolean haveNewUpdate) {
                if (haveNewUpdate) {
                    Log.d(TAG, "Update available");
                    int permission = ContextCompat.checkSelfPermission(
                        context, Manifest.permission.WRITE_EXTERNAL_STORAGE
                    );

                    // don't have permissions, so need to request
                    if (permission != PackageManager.PERMISSION_GRANTED) {
                        Log.d(TAG, "Requesting permissions...");

                        new AlertDialog.Builder(activity)
                            .setTitle("Update Available")
                            .setMessage(
                                "A new version of X-Ray is available. " +
                                "Would you like to download it now? " +
                                "(Requires permissions to write to storage)"
                            )
                            .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialogInterface, int i) {
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
                    }
                    // already have permissions, start update immediately
                    else {
                        Log.d(TAG, "Already have permissions, skipping request procedure");
                        startUpdateTask();
                    }
                }
            }
        });
        checkTask.execute();
    }

    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            // user gave us permission to write to external storage, so kick off update task
            startUpdateTask();
        } else {
            Log.d(TAG, "Update request denied by user");
        }
    }

    public static boolean writeToOutputStream (InputStream inputStream, OutputStream outputStream) {
        byte[] buffer = new byte[4096];
        int nRead;

        try {
            while ((nRead = inputStream.read(buffer, 0, buffer.length)) > 0) {
                outputStream.write(buffer, 0, nRead);
            }
            outputStream.flush();
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}
