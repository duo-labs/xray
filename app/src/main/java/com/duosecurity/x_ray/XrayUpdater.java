package com.duosecurity.x_ray;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
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

    public static final String BASE_URL = "https://labs.duo.com/xray";
    public final static String DOWNLOAD_URL = BASE_URL + "/dl";
    public final static String VERSION_URL = BASE_URL + "/version";

    public final static String DOWNLOAD_DIR = "/Download/";
    public final static String FILE_TYPE = "application/vnd.android.package-archive";

    public static final String SERVER_PUB_KEY =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy5bOzkZ36VV+kjSYso0HTCZwHWMT\n" +
        "29lQWpJYAiudtZ65mdcBCgmsB/jAwLIJl8BricbLhGU9FA/Wxha5b3ee7A==";

    public static final String[] CERT_PINS = {
        "de52af8cdb1f9ab9fe5a67c386faf689587fc91b" // C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA
    };

    public enum CheckResult {
        UP_TO_DATE, OUT_OF_DATE, SSL_ERROR
    }
    public enum UpdateResult {
        DOWNLOAD_SUCCESS, DOWNLOAD_ERROR, SSL_ERROR
    }

    private static final String SHARED_PREFERENCES = "X-Ray";
    private static SharedPreferences sharedPreferences = null;

    public XrayUpdater(Activity act) {
        activity = act;
        context = activity.getApplicationContext();
        sharedPreferences = activity.getSharedPreferences(SHARED_PREFERENCES, context.MODE_PRIVATE);
    }

    public static void setSharedPreference(String preference, String value) {
        sharedPreferences.edit().putString(preference, value).commit();
    }

    public static String getSharedPreference(String preference) {
        return sharedPreferences.getString(preference, "");
    }

    private void displayUpdateErrorPrompt() {
        new AlertDialog.Builder(activity)
            .setTitle("Unable to update")
            .setCancelable(false)
            .setMessage(
                "Something is interfering with your secure connection to the update server.\n\n" +
                "Try downloading a new version of X-Ray from https://xray.io.\n\n" +
                "If the problem persists, try connecting to a different network."
            )
            .setPositiveButton("Download now", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialogInterface, int i) {
                    Uri downloadUri = Uri.parse(DOWNLOAD_URL);
                    Intent browserIntent = new Intent(Intent.ACTION_VIEW, downloadUri);
                    browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    activity.startActivity(browserIntent);
                }
            })
            .setNegativeButton("Later", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialogInterface, int i) {
                    dialogInterface.dismiss();
                }
            })
            .show();
    }

    private void startUpdateTask() {
        XrayUpdateTask updateTask = new XrayUpdateTask(context, new XrayUpdateTask.TaskListener() {
            @Override
            public void onFinished(UpdateResult updateResult) {
                if (updateResult != UpdateResult.DOWNLOAD_SUCCESS) {
                    displayUpdateErrorPrompt();
                }
            }
        });
        updateTask.execute();
    }

    public void startCheckTask() {
        Log.d(TAG, "Checking for updates...");

        XrayCheckTask checkTask = new XrayCheckTask(context, new XrayCheckTask.TaskListener() {
            @Override
            public void onFinished(CheckResult checkResult) {
                if (checkResult == CheckResult.SSL_ERROR) {
                    displayUpdateErrorPrompt();
                }
                else if (checkResult == CheckResult.OUT_OF_DATE) {
                    Log.d(TAG, "Update available");

                    new AlertDialog.Builder(activity)
                        .setTitle("Update Available")
                        .setMessage(
                            "A new version of X-Ray is available. " +
                            "Would you like to download it now?\n" +
                            "(Requires permissions to write to storage)"
                        )
                        .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialogInterface, int i) {
                                int permission = ContextCompat.checkSelfPermission(
                                    context, Manifest.permission.WRITE_EXTERNAL_STORAGE
                                );

                                // don't have permissions, so need to request
                                if (permission != PackageManager.PERMISSION_GRANTED) {
                                    Log.d(TAG, "Requesting permissions...");

                                    ActivityCompat.requestPermissions(
                                        activity,
                                        PERMISSIONS_STORAGE,
                                        REQUEST_EXTERNAL_STORAGE
                                    );
                                }
                                // already have permissions, start update immediately
                                else {
                                    Log.d(TAG, "Already have permissions, skipping request procedure");
                                    startUpdateTask();
                                }
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
