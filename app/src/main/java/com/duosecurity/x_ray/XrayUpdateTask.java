package com.duosecurity.x_ray;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Environment;
import android.util.Log;

import com.duosecurity.duokit.crypto.Crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;

public class XrayUpdateTask extends AsyncTask<Void, Void, Void> {

    private final static String TAG = XrayUpdateTask.class.getSimpleName();

    protected Context context = null;
    private Crypto crypto = null;

    public XrayUpdateTask(Context ctx) {
        context = ctx;
        crypto = Crypto.getInstance();
    }

    private String getFileChecksum (String fullPath) {
        String result = null;
        InputStream inputStream = null;

        try {
            MessageDigest md = MessageDigest.getInstance(XrayUpdater.CHECKSUM_ALGORITHM);
            inputStream = new FileInputStream(fullPath);

            byte[] buffer = new byte[4096];
            int nRead;

            while ((nRead = inputStream.read(buffer, 0, buffer.length)) > 0) {
                md.update(buffer, 0, nRead);
            }

            result = crypto.hex(md.digest());

        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Unable to get digest instance when calculating apk checksum");
        } catch (FileNotFoundException e) {
            Log.d(TAG, "Unable to find apk file when calculating apk checksum");
        } catch (IOException e) {
            Log.d(TAG, "Unable to read apk file when calculating apk checksum");
        } catch (Exception e) {
            Log.d(TAG, "Found error when calculating apk checksum: " + e.toString());
        } finally {
            Log.d(TAG, "Cleaning up after calculating apk checksum...");
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    Log.d(TAG, "Found IO exception when trying to close inputstream: " + e.toString());
                }
            }
        }
        return result;
    }

    protected void promptInstall (String filePath) {
        Intent installIntent = new Intent(Intent.ACTION_VIEW)
            .setDataAndType(Uri.parse("file://" + filePath), XrayUpdater.FILE_TYPE)
            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(installIntent);
    }

    protected Void doInBackground (Void... v) {
        HttpsURLConnection urlConnection = null;
        InputStream inputStream = null;

        Log.d(TAG, "Attempting to fetch apk update...");

        try {
            // make sure necessary info has been set
            String apkName = XrayUpdater.getSharedPreference("apkName");
            String actualChecksum = XrayUpdater.getSharedPreference("apkChecksum");
            if ("".equals(apkName) || "".equals(actualChecksum)) {
                throw new Exception("Missing apkName or apkChecksum");
            }

            // issue GET request to download new apk
            URL url = new URL(XrayUpdater.DOWNLOAD_URL);
            urlConnection = (HttpsURLConnection) url.openConnection();
            urlConnection.setConnectTimeout(XrayUpdater.CONNECTION_TIMEOUT);
            urlConnection.setReadTimeout(XrayUpdater.READ_TIMEOUT);
            urlConnection.setRequestMethod("GET");
            urlConnection.setDoInput(true);
            urlConnection.connect();

            int responseCode = urlConnection.getResponseCode();
            String responseType = urlConnection.getContentType();

            if (responseCode != HttpsURLConnection.HTTP_OK ||
                !responseType.equalsIgnoreCase(XrayUpdater.FILE_TYPE)) {
                throw new Exception("Error fetching apk update");
            }

            String storagePath = Environment.getExternalStorageDirectory().getAbsolutePath();
            // join storagePath and download directory
            String downloadPath = new File(storagePath, XrayUpdater.DOWNLOAD_DIR).getAbsolutePath();
            // create download dir if doesn't exist
            File directory = new File(downloadPath);
            directory.mkdirs();

            // write the results into an apk file
            File outputFile = new File(directory, apkName);
            if (!outputFile.exists()) {
                outputFile.createNewFile();
            }
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            inputStream = urlConnection.getInputStream();
            boolean writeSuccess = XrayUpdater.writeToOutputStream(inputStream, outputStream);

            if (writeSuccess) {
                String fullPath = outputFile.getAbsolutePath();

                // verify checksum of apk
                String calculatedChecksum = getFileChecksum(fullPath);

                if (actualChecksum.equals(calculatedChecksum)) {
                    Log.d(TAG, "Checksum of apk file valid. Prompting install...");
                    promptInstall(fullPath);
                } else {
                    Log.d(TAG, "Checksum of apk file invalid, deleting apk file");
                    outputFile.delete();
                }
            } else {
                Log.d(TAG, "Unable to write apk when trying to update, apk likely corrupted");
            }
        } catch (MalformedURLException e) {
            Log.d(TAG, "Found malformed URL when trying to update");
        } catch (SocketTimeoutException e) {
            Log.d(TAG, "Socket timed out when trying to update: " + e.toString());
        } catch (IOException e) {
            Log.d(TAG, "Found IO exception when trying to update: " + e.toString());
        } catch (Exception e) {
            Log.d(TAG, "Received error when trying to update: " + e.toString());
        } finally {
            Log.d(TAG, "Cleaning up update task...");

            // close the GET connection
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    Log.d(TAG, "Found IO exception when trying to close inputstream: " + e.toString());
                }
            }
            if (urlConnection != null) {
                urlConnection.disconnect();
            }

            Log.d(TAG, "Exiting update task");
        }
        return null;
    }
}
