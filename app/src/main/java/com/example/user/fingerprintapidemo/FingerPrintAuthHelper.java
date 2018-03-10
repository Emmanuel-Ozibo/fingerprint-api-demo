package com.example.user.fingerprintapidemo;

import android.content.Context;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.security.keystore.KeyProperties;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

/**
 * Created by emmanuel on 3/7/2018.
 */

public class FingerPrintAuthHelper extends FingerprintManager.AuthenticationCallback{
    private Context context;
    private KeyStore keyStore;
    private FingerPrintAuthListener listener;

    public FingerPrintAuthHelper(Context context, KeyStore keyStore, FingerPrintAuthListener listener) {
        this.context = context;
        this.keyStore = keyStore;
        this.listener = listener;
    }

    /**
     * @param manager This is the fingerPrint manager instance
     * @param cryptoObject This contains all the cryptography params(key, clipper etc)
     * */

    public void authenticate(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject){

        CancellationSignal cancellationSignal = new CancellationSignal();
        manager.authenticate(cryptoObject,
                cancellationSignal,
                0,
                this,
                null);

    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        listener.onSuccessful();
    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        listener.failed();
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);
        listener.error();
    }

    public interface FingerPrintAuthListener{
        void onSuccessful();
        void failed();
        void error();
    }
}
