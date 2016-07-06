package com.duosecurity.x_ray;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Environment;
import android.util.JsonReader;
import android.util.Log;

import com.duosecurity.duokit.crypto.Crypto;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;

public class XrayUpdateTask extends AsyncTask<Void, Void, Void> {

    private final static String TAG = XrayUpdateTask.class.getSimpleName();

    private final static String ECDSA_ALGORITHM = "SHA256withECDSA";
    private final static String ECDSA_PROVIDER = "SC"; // spongycastle

    private final static int CONNECTION_TIMEOUT = 15000;
    private final static int READ_TIMEOUT = 15000;

    private final static String DOWNLOAD_URL = "http://10.0.2.2:8080/xray/dl";
    private final static String VERSION_URL = "http://10.0.2.2:8080/xray/version";

    private final static String DOWNLOAD_DIR = "/Download/";
    private final static String FILE_TYPE = "application/vnd.android.package-archive";

    private final static String SERVER_PUB_KEY =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy5bOzkZ36VV+kjSYso0HTCZwHWMT\n" +
        "29lQWpJYAiudtZ65mdcBCgmsB/jAwLIJl8BricbLhGU9FA/Wxha5b3ee7A==";

    protected Context context = null;
    private Crypto crypto = null;

    public XrayUpdateTask(Context ctx) {
        context = ctx;
        crypto = Crypto.getInstance();
    }

    private boolean writeToOutputStream (InputStream inputStream, OutputStream outputStream) {
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

    private String getFileChecksum (String fullPath) {
        String result = null;

        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            InputStream inputStream = new FileInputStream(fullPath);

            byte[] buffer = new byte[4096];
            int nRead;

            while ((nRead = inputStream.read(buffer, 0, buffer.length)) > 0) {
                md.update(buffer, 0, nRead);
            }

            inputStream.close();
            result = crypto.hex(md.digest());

        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Unable to get MD5 digest instance when calculating apk checksum");
        } catch (FileNotFoundException e) {
            Log.d(TAG, "Unable to find apk file when calculating apk checksum");
        } catch (IOException e) {
            Log.d(TAG, "Unable to read apk file when calculating apk checksum");
        } catch (Exception e) {
            Log.d(TAG, "Found error when calculating apk checksum: " + e.getMessage());
        }
        return result;
    }

    protected void promptInstall (String filePath) {
        Intent installIntent = new Intent(Intent.ACTION_VIEW)
            .setDataAndType(Uri.parse("file://" + filePath), FILE_TYPE)
            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(installIntent);
    }

    protected Void doInBackground (Void... v) {
        HttpURLConnection urlConnection;

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

            int responseCode = urlConnection.getResponseCode();
            int latestVersion = -1;
            String fileName = null;
            String md5Hash = null;

            // read the results into a byte array stream
            InputStream inputStream = new BufferedInputStream(urlConnection.getInputStream());
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.d(TAG, "Error fetching app version, HTTP request returned: " + responseCode);
            }
            else if (!writeToOutputStream(inputStream, byteStream)) {
                Log.d(TAG, "Error fetching app version, invalid input stream");
            }
            else {
                // request looks okay, let's verify response signature
                Signature ecdsaSignature = Signature.getInstance(ECDSA_ALGORITHM, ECDSA_PROVIDER);
                PublicKey extPubKey = crypto.readPublicKey(SERVER_PUB_KEY);
                ecdsaSignature.initVerify(extPubKey);
                ecdsaSignature.update(byteStream.toByteArray());

                String signature = urlConnection.getHeaderField("Xray-Signature");
                byte[] signature_bytes = crypto.base64Decode(signature);

                if (!ecdsaSignature.verify(signature_bytes)) {
                    Log.d(TAG, "Invalid signature");
                }
                else {
                    Log.d(TAG, "Signature valid. Reading JSON response...");

                    // signature is valid, so read version and filename from JSON response
                    inputStream = new ByteArrayInputStream(byteStream.toByteArray());
                    JsonReader reader = new JsonReader(new InputStreamReader(inputStream));
                    reader.beginObject();
                    while (reader.hasNext()) {
                        String key = reader.nextName();
                        if (key.equals("apkVersion")) {
                            latestVersion = Integer.parseInt(reader.nextString());
                        } else if (key.equals("apkName")) {
                            fileName = reader.nextString();
                        } else if (key.equals("md5")) {
                            md5Hash = reader.nextString();
                        } else {
                            reader.skipValue();
                        }
                    }
                    reader.endObject();
                }
            }

            // close the GET connection
            inputStream.close();
            urlConnection.disconnect();

            if (latestVersion < 0 || fileName == null || md5Hash == null) {
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
                boolean writeSuccess = writeToOutputStream(inputStream, outputStream);

                inputStream.close();
                outputStream.close();

                if (writeSuccess) {
                    String fullPath = outputFile.getAbsolutePath();

                    // verify md5 hash of apk
                    String calcChecksum = getFileChecksum(fullPath);

                    if (md5Hash.equals(calcChecksum)) {
                        Log.d(TAG, "MD5 checksum of apk file valid. Prompting install...");
                        promptInstall(fullPath);
                    } else {
                        Log.d(TAG, "MD5 checksum of apk file invalid, deleting apk file");
                        outputFile.delete();
                    }
                } else {
                    Log.d(TAG, "Unable to write apk when trying to update, apk likely corrupted");
                }
            } else {
                Log.d(TAG, "Already up to date");
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
            Log.d(TAG, "Exiting updater");
        }
        return null;
    }
}
