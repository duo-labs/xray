package com.duosecurity.x_ray;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Environment;
import android.util.JsonReader;
import android.util.Log;

import org.json.JSONException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.Scanner;
import java.util.jar.JarFile;

public class XrayUpdateTask extends AsyncTask<Void, Void, Void> {

    private final static String TAG = "XrayUpdateTask";

    private final static int CONNECTION_TIMEOUT = 15000;
    private final static int READ_TIMEOUT = 15000;

    private final static String DOWNLOAD_URL = "http://10.0.2.2:8080/xray/dl";
    private final static String VERSION_URL = "http://10.0.2.2:8080/xray/version";

    private final static String DOWNLOAD_DIR = "/Download/";
    private final static String FILE_TYPE = "application/vnd.android.package-archive";

    protected Context context = null;

    public XrayUpdateTask(Context ctx) {
        context = ctx;
    }

    protected void promptInstall (String filePath) {
        Intent installIntent = new Intent(Intent.ACTION_VIEW)
            .setDataAndType(Uri.parse("file://" + filePath), FILE_TYPE)
            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(installIntent);
    }

    protected Void doInBackground (Void... v) {
        HttpURLConnection urlConnection = null;

        Log.d(TAG, "Checking for new updates...");

        try {
            // issue a GET request to determine the latest available apk version
            URL url = new URL(VERSION_URL);
            urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setConnectTimeout(CONNECTION_TIMEOUT);
            urlConnection.setReadTimeout(READ_TIMEOUT);
            urlConnection.setRequestMethod("GET");
            urlConnection.setDoInput(true);
            urlConnection.connect();

            // read the results into a string
            InputStream inputStream = new BufferedInputStream(urlConnection.getInputStream());
            int responseCode = urlConnection.getResponseCode();
            int latestVersion = -1;
            String fileName = null;

            if (responseCode == HttpURLConnection.HTTP_OK) {
                // read version and filename from JSON response
                JsonReader reader = new JsonReader(new InputStreamReader(inputStream));
                reader.beginObject();
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    if (key.equals("apkVersion")) {
                        latestVersion = Integer.parseInt(reader.nextString());
                    } else if (key.equals("apkName")) {
                        fileName = reader.nextString();
                    } else {
                        reader.skipValue();
                    }
                }
                reader.endObject();
            } else {
                Log.d(TAG, "Error fetching app version, HTTP request returned: " + responseCode);
            }

            // close the GET connection
            inputStream.close();
            urlConnection.disconnect();

            if (latestVersion < 0 || fileName == null) {
                Log.d(TAG, "Error fetching app version, JSON response missing fields");
                return null;
            }

            // check whether we are out of date
            if (latestVersion > 0 && latestVersion != BuildConfig.VERSION_CODE) {
                Log.d(TAG, "Attempting to fetch apk update");

                // our current version is outdated, issue new GET request to download new apk
                url = new URL(DOWNLOAD_URL);
                urlConnection = (HttpURLConnection) url.openConnection();
                urlConnection.setConnectTimeout(CONNECTION_TIMEOUT);
                urlConnection.setReadTimeout(READ_TIMEOUT);
                urlConnection.setRequestMethod("GET");
                urlConnection.setDoInput(true);
                urlConnection.connect();

                responseCode = urlConnection.getResponseCode();
                String responseType = urlConnection.getContentType();

                if (responseCode != HttpURLConnection.HTTP_OK ||
                        !responseType.equalsIgnoreCase(FILE_TYPE)) {
                    Log.d(TAG, "Error fetching apk update");
                    return null;
                }

                // read the results into an apk file
                String storagePath = Environment.getExternalStorageDirectory().getAbsolutePath();
                // join storagePath and download directory
                String downloadPath = new File(storagePath, DOWNLOAD_DIR).getAbsolutePath();
                // create download dir if doesn't exist
                File directory = new File(downloadPath);
                directory.mkdirs();
                File outputFile = new File(directory, fileName);
                if (!outputFile.exists()) {
                    outputFile.createNewFile();
                }
                FileOutputStream outputStream = new FileOutputStream(outputFile);
                inputStream = urlConnection.getInputStream();

                byte[] buffer = new byte[4096];
                int nRead;
                while ((nRead = inputStream.read(buffer, 0, buffer.length)) > 0) {
                    outputStream.write(buffer, 0, nRead);
                }

                inputStream.close();
                outputStream.close();

                String fullPath = outputFile.getAbsolutePath();

                // will throw an exception if apk file is corrupted
                new JarFile(fullPath);

                // display installation prompt
                promptInstall(fullPath);
            } else {
                Log.d(TAG, "Already up to date");
            }
        } catch (MalformedURLException e) {
            Log.d(TAG, "Found malformed URL when trying to update");
        } catch (SocketTimeoutException e) {
            Log.d(TAG, "Socket timed out when trying to update: " + e.toString());
        } catch (IOException e) {
            Log.d(TAG, "Update failed with error: " + e.toString());
        } catch (Exception e) {
            Log.d(TAG, "Apk file is corrupted, or unknown error: " + e.toString());
        } finally {
            Log.d(TAG, "Exiting updater");
        }
        return null;
    }
}
