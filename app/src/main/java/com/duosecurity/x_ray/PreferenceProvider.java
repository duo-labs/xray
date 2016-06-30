package com.duosecurity.x_ray;

import android.content.SharedPreferences;
import com.duosecurity.x_ray.preferences.StringPreference;

public class PreferenceProvider {

    public static StringPreference provide_ext_pubkey(SharedPreferences preferences) {
        return new StringPreference(preferences, "ext_pubkey");
    }

    public static StringPreference provide_mobile_pubkey(SharedPreferences preferences) {
        return new StringPreference(preferences, "mobile_pubkey");
    }

    public static StringPreference provide_mobile_privkey(SharedPreferences preferences) {
        return new StringPreference(preferences, "mobile_privkey");
    }

    public static StringPreference provide_shared_secret(SharedPreferences preferences) {
        return new StringPreference(preferences, "shared_secret");
    }

    private PreferenceProvider () {}
}
