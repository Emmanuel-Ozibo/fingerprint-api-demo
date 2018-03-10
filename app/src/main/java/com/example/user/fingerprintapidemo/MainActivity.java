package com.example.user.fingerprintapidemo;

import android.app.KeyguardManager;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity implements FingerPrintAuthHelper.FingerPrintAuthListener{
    public static final String KEY_STORE_NAME = "keyStoreName";

    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;
    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private TextView statusTv;

    @Override
    protected void onCreate(Bundle savedInstanceState){
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusTv = findViewById(R.id.statusTv);

        fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
        keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);

        startFingerPrintAuth();

    }

    private void startFingerPrintAuth() {
        if (checkFingerPrintInfo()) {
            //get the key
            generateKeyInAndroidKeyStore();
            //initialise the cipher -> used for encryption
            Cipher cipher = initialiseCipherObject();
            //get the cryptoObject
            FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
            //get an instance of the finger print helper class and do the authentication
            FingerPrintAuthHelper fingerPrintAuthHelper = new FingerPrintAuthHelper(this, keyStore, this);
            fingerPrintAuthHelper.authenticate(fingerprintManager, cryptoObject);
        }else {
            Toast.makeText(this, "Insufficient Infomation, Can;t continue with the fingerPrint Auto", Toast.LENGTH_LONG).show();
        }
    }

    private Cipher initialiseCipherObject() {
        Cipher cipher = null;
        String transformation = KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7;
        try {
            cipher = Cipher.getInstance(transformation);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }

        try {
            String message = "This is the message i want send";
            byte[] messageByte = message.getBytes();
            //get the keystore instance, do we can get a key from it
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_STORE_NAME, null);
            //get the cipher to use this secret key to encrypt the message
            if (cipher != null) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                cipher.doFinal(messageByte);
            }


        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return cipher;
    }

    private void generateKeyInAndroidKeyStore(){
        //get the instance of the android keystore
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            //create an instance of keyGenerator -> used to generate keys in keystore
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            //load the keystore
            keyStore.load(null);
            //generate the key using the keyGenerator, firstly we build the params  required to generate key
            KeyGenParameterSpec keyGenParameterSpec = getKeyGenParamsSpec();
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private KeyGenParameterSpec getKeyGenParamsSpec() {
        //This uses a builder design pattern
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_STORE_NAME,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC);
        builder.setUserAuthenticationRequired(true);
        builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

        return builder.build();
    }

    private boolean checkFingerPrintInfo(){
        //check if the key guard is actively secured
        if (isKeyGuardSecured()){
            Log.i("keyGuardSecurityStatus","secured");
            //check if the fingerPrint hardware is present in the device
            if (fingerprintManager.isHardwareDetected()){
                Log.i("fingerPrintHardware", "present");
                //check if at least one finger print is already registered on the device
                if (fingerprintManager.hasEnrolledFingerprints()){
                    Log.i("enrolled","yes");
                    return true;
                }else {
                    Toast.makeText(this, "goto your device settings, and register a finger print", Toast.LENGTH_LONG).show();
                }
            }else {
                Toast.makeText(this, "Sorry your device does not have a finger print hardware", Toast.LENGTH_LONG).show();
            }

        }else {
            Toast.makeText(this, "Set up a password, PIN, or Pattern..", Toast.LENGTH_LONG).show();
        }
        return false;
    }

    private boolean isKeyGuardSecured(){
        return keyguardManager.isKeyguardSecure();
    }

    @Override
    public void onSuccessful() {
        startActivity(new Intent(this, AuthenticatedActivity.class));
    }

    @Override
    public void failed() {
        statusTv.setText("Failed");
        startFingerPrintAuth();
    }

    @Override
    public void error() {
        statusTv.setText("Error");
        startFingerPrintAuth();
    }
}
