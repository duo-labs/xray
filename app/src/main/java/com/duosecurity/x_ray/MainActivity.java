package com.duosecurity.x_ray;

import com.duosecurity.x_ray.device.vulnerability.test.adapter.RecyclerAdapter;

import fuzion24.device.vulnerability.test.ResultsCallback;
import fuzion24.device.vulnerability.test.VulnerabilityTestResult;
import fuzion24.device.vulnerability.test.VulnerabilityTestRunner;
import fuzion24.device.vulnerability.util.DeviceInfo;

import com.duosecurity.x_ray.device.vulnerability.vulnerabilities.VulnerabilityResultSerializer;

import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends ActionBarActivity {

    private static final String SERIALIZABLE_RESULTS = "SERIALIZABLE_RESULTS";

    private static final String TAG = "VULN_TEST";
    private static final String DEBUG = "DEBUG";

    private DeviceInfo devInfo;
    private ArrayList<VulnerabilityTestResult> testResults;
    private RecyclerView recyclerView;
    private RecyclerAdapter recyclerAdapter;

    private XrayUpdater updater;

    @Override
    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        if (requestCode == XrayUpdater.REQUEST_EXTERNAL_STORAGE) {
            updater.onRequestPermissionsResult(requestCode, permissions, grantResults);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // run update routine
        updater = new XrayUpdater(MainActivity.this);
        updater.checkForUpdates();

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if (savedInstanceState != null && savedInstanceState.containsKey(SERIALIZABLE_RESULTS)) {
            testResults = (ArrayList<VulnerabilityTestResult>) savedInstanceState.getSerializable(SERIALIZABLE_RESULTS);
        } else {
            testResults = new ArrayList<>();
        }

        recyclerView = (RecyclerView) findViewById(R.id.recyclerView);
        recyclerAdapter = new RecyclerAdapter(MainActivity.this, testResults);

        recyclerView.setLayoutManager(new LinearLayoutManager(MainActivity.this));
        recyclerView.setAdapter(recyclerAdapter);

        devInfo = DeviceInfo.getDeviceInfo();

        Button fabStart = (Button) findViewById(R.id.fabStart);

        fabStart.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Button fabStart = (Button) findViewById(R.id.fabStart);
                fabStart.setVisibility(View.GONE);
                runTestSuite();
            }
        });
    }

    private void runTestSuite() {
        new VulnerabilityTestRunner(MainActivity.this, true, new ResultsCallback() {
            @Override
            public void finished(final List<VulnerabilityTestResult> results) {
                Log.d(TAG, "Device Vulnerability callback, finished");

                testResults.clear();
                testResults.addAll(results);

                recyclerAdapter.updateResults(results);

                new HttpAsyncTask().execute("https://duo-xray-server.appspot.com/Wut");
            }
        }).execute();
    }


    private class HttpAsyncTask extends AsyncTask<String, Void, String> {
        @Override
        protected String doInBackground(String... urls) {
            return POST(urls[0]);
        }
    }

    public String POST(String url) {
        InputStream inputStream = null;
        String result = "";
        try {
            // 1. create HttpClient
            HttpClient httpclient = new DefaultHttpClient();

            // 2. make POST request to the given URL
            HttpPost httpPost = new HttpPost(url);

            String json = "";

            // 3. build jsonObject

            JSONObject jsonObject = VulnerabilityResultSerializer.serializeResultsToJson(testResults, devInfo);

            // 4. convert JSONObject to JSON to String
            json = jsonObject.toString(4);
            Log.d(DEBUG, json);
            // 5. set json to StringEntity
            StringEntity se = new StringEntity(json);

            // 6. set httpPost Entity
            httpPost.setEntity(se);

            // 7. Set some headers to inform server about the type of the content
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");

            // 8. Execute POST request to the given URL
            HttpResponse httpResponse = httpclient.execute(httpPost);

            // 9. receive response as inputStream
            inputStream = httpResponse.getEntity().getContent();

            // 10. convert inputstream to string
            if (inputStream != null)
                result = convertInputStreamToString(inputStream);
            else
                result = "Did not work!";
            //Log.d(DEBUG, result);
        } catch (Exception e) {
            Log.d("InputStream", e.getLocalizedMessage());
        }

        // 11. return result
        return result;
    }

    private static String convertInputStreamToString(InputStream inputStream) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        String line = "";
        String result = "";
        while ((line = bufferedReader.readLine()) != null)
            result += line;

        inputStream.close();
        return result;

    }
}
