package com.duosecurity.x_ray;

import android.os.AsyncTask;
import android.util.JsonReader;
import android.util.Log;

import com.duosecurity.duokit.crypto.Crypto;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.PublicKey;
import java.security.Signature;

public class XrayCheckTask extends AsyncTask<Void, Void, Boolean> {

    private final static String TAG = XrayCheckTask.class.getSimpleName();

    private Crypto crypto = null;
    private TaskListener callback = null;

    public interface TaskListener {
        void onFinished(Boolean haveNewUpdate);
    }

    public XrayCheckTask (TaskListener taskListener) {
        crypto = Crypto.getInstance();
        callback = taskListener;
    }

    @Override
    protected Boolean doInBackground (Void... v) {
        HttpURLConnection urlConnection;

        Log.d(TAG, "Attempting to fetch manifest...");

        try {
            // issue a GET request to determine the latest available apk version
            URL url = new URL(XrayUpdater.VERSION_URL);
            urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setConnectTimeout(XrayUpdater.CONNECTION_TIMEOUT);
            urlConnection.setReadTimeout(XrayUpdater.READ_TIMEOUT);
            urlConnection.setRequestMethod("GET");
            urlConnection.setDoInput(true);
            urlConnection.connect();

            int responseCode = urlConnection.getResponseCode();
            int apkVersion = -1;
            String apkName = null;
            String checksum = null;

            // read the results into a byte array stream
            InputStream inputStream = new BufferedInputStream(urlConnection.getInputStream());
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.d(TAG, "Error fetching app version, HTTP request returned: " + responseCode);
            }
            else if (!XrayUpdater.writeToOutputStream(inputStream, byteStream)) {
                Log.d(TAG, "Error fetching app version, invalid input stream");
            }
            else {
                // request looks okay, let's verify response signature
                Signature ecdsaSignature = Signature.getInstance(
                    XrayUpdater.ECDSA_ALGORITHM, XrayUpdater.ECDSA_PROVIDER
                );
                PublicKey extPubKey = crypto.readPublicKey(XrayUpdater.SERVER_PUB_KEY);
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
                            apkVersion = Integer.parseInt(reader.nextString());
                        } else if (key.equals("apkName")) {
                            apkName = reader.nextString();
                        } else if (key.equals("md5")) {
                            checksum = reader.nextString();
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

            if (apkVersion < 0 || apkName == null || checksum == null) {
                Log.d(TAG, "Error fetching app version, JSON response missing fields");
            }
            else if (apkVersion == BuildConfig.VERSION_CODE) {
                Log.d(TAG, "Already up to date");
            }
            else { // out of date
                XrayUpdater.setSharedPreference("apkName", apkName);
                XrayUpdater.setSharedPreference("checksum", checksum);
                return true;
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
            Log.d(TAG, "Exiting check task");
        }
        return false;
    }

    @Override
    protected void onPostExecute(Boolean haveNewUpdate) {
        super.onPostExecute(haveNewUpdate);

        if (callback != null) {
            callback.onFinished(haveNewUpdate);
        }
    }
}
