package com.duosecurity.x_ray.preferences;

import android.content.SharedPreferences;

public class StringPreference {
    private final SharedPreferences preferences;
    private final String key;
    private final String defaultValue;

    public StringPreference(SharedPreferences preferences, String key) {
        this(preferences, key, "");
    }

    public StringPreference(SharedPreferences preferences, String key, String defaultValue) {
        this.preferences = preferences;
        this.key = key;
        this.defaultValue = defaultValue;
    }

    public String get() {
        return preferences.getString(key, defaultValue);
    }

    public boolean isSet() { return preferences.contains(key); }

    public void set(String value) {
        preferences.edit().putString(key, value).commit();
    }

    public void delete() {
        preferences.edit().remove(key).commit();
    }
}
