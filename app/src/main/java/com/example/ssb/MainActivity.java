package com.example.ssb;

import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;

import com.android.apksig.ApkSigner;
import com.reandroid.apk.ApkModule;
import com.reandroid.app.AndroidManifest;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.security.auth.x500.X500Principal;

public class MainActivity extends AppCompatActivity {

    private static final int FILE_CHOOSER_RESULT_CODE = 1;
    private static final String SKELETON_ASSET_NAME = "skeleton.apk";
    private static final String TEST_KEY_ALIAS = "ssb_test_key";

    private static final String FALLBACK_CONFIG =
            "const config = {\n" +
            "external: [],\n" +
            "startURL: \"\",\n" +
            "broAgent: \"\",\n" +
            "portrait: true,\n" +
            "screenOn: false,\n" +
            "allowZoom: false,\n" +
            "forceDark: false,\n" +
            "refreshOn: false,\n" +
            "scrollBar: true,\n" +
            "mobilView: true,\n" +
            "background: false\n" +
            "};";

    private WebView webView;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private ValueCallback<Uri[]> uploadMessage;
    private volatile boolean buildCancelled = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        webView.setBackgroundColor(Color.BLACK);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(true);
        webView.getSettings().setAllowFileAccess(true);

        webView.addJavascriptInterface(new WebAppInterface(this), "AndroidBridge");
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                executor.execute(() -> sendDefaultConfigToUi());
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(
                    WebView webView,
                    ValueCallback<Uri[]> filePathCallback,
                    FileChooserParams fileChooserParams
            ) {
                if (uploadMessage != null) {
                    uploadMessage.onReceiveValue(null);
                    uploadMessage = null;
                }
                uploadMessage = filePathCallback;

                Intent intent = fileChooserParams.createIntent();
                try {
                    startActivityForResult(intent, FILE_CHOOSER_RESULT_CODE);
                } catch (ActivityNotFoundException e) {
                    uploadMessage = null;
                    showAlert("Error", "No file picker application found.");
                    return false;
                }
                return true;
            }
        });

        webView.loadUrl("file:///android_asset/index.html");
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
        super.onActivityResult(requestCode, resultCode, intent);
        if (requestCode == FILE_CHOOSER_RESULT_CODE) {
            if (uploadMessage == null) return;
            Uri[] results = null;
            if (resultCode == RESULT_OK && intent != null && intent.getDataString() != null) {
                results = new Uri[]{Uri.parse(intent.getDataString())};
            }
            uploadMessage.onReceiveValue(results);
            uploadMessage = null;
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        buildCancelled = true;
        executor.shutdownNow();
    }

    private void sendDefaultConfigToUi() {
        String content = readDefaultConfigContent();
        String encoded = Base64.encodeToString(content.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        mainHandler.post(() -> webView.evaluateJavascript(
                "setDefaultConfigContent(decodeURIComponent(escape(atob('" + encoded + "'))));",
                null
        ));
    }

    private String readDefaultConfigContent() {
        try (InputStream is = getAssets().open("appConfig.js")) {
            return readStreamToString(is);
        } catch (IOException ignored) {
            return FALLBACK_CONFIG;
        }
    }

    private void buildLocalApkWithArsclibAndSign(
            String appName,
            String packageName,
            String iconBase64,
            String startUrl,
            String configContent,
            String sdkMin,
            String sdkMax,
            String importedApkBase64
    ) {
        buildCancelled = false;
        try {
            if (packageName == null || !packageName.matches("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$")) {
                throw new IllegalArgumentException("Invalid package name (e.g. com.example.myapp).");
            }

            File workDir = new File(getCacheDir(), "local_build");
            if (workDir.exists()) {
                deleteRecursive(workDir);
            }
            //noinspection ResultOfMethodCallIgnored
            workDir.mkdirs();

            File sourceApk = prepareSourceApkFile(workDir, importedApkBase64);
            File arscModifiedApk = new File(workDir, "arsc_modified.apk");
            File rawPackagedApk = new File(workDir, "raw_packaged.apk");
            File signedOutApk = getOutputApkFile();

            logToUi("[INFO] Loading APK with ARSCLib: " + sourceApk.getName());
            ApkModule module = ApkModule.loadApkFile(sourceApk);

            if (module.hasAndroidManifest()) {
                AndroidManifest manifest = module.getAndroidManifest();
                manifest.setPackageName(packageName);

                if (sdkMin != null && !sdkMin.isEmpty()) {
                    try {
                        manifest.setMinSdkVersion(Integer.parseInt(sdkMin));
                    } catch (Exception ignored) {
                    }
                }
                if (sdkMax != null && !sdkMax.isEmpty()) {
                    try {
                        manifest.setTargetSdkVersion(Integer.parseInt(sdkMax));
                    } catch (Exception ignored) {
                    }
                }
            }

            if (buildCancelled) {
                module.close();
                return;
            }

            logToUi("[INFO] Writing modified manifest/resources..");
            module.writeApk(arscModifiedApk);
            module.close();

            byte[] iconBytes = decodeBase64Image(iconBase64);
            byte[] configBytes = buildFinalConfigBytes(configContent, startUrl);

            logToUi("[INFO] Updating assets/appConfig.js and icon entries..");
            updateZipEntries(arscModifiedApk, rawPackagedApk, configBytes, iconBytes);

            if (buildCancelled) return;

            logToUi("[INFO] Signing APK with Google ApkSigner (test key)..");
            signApkWithGoogleApksig(rawPackagedApk, signedOutApk);

            logToUi("[SUCCESS] Signed APK ready: " + signedOutApk.getAbsolutePath());
            setReadyUi();
        } catch (Exception e) {
            if (buildCancelled) {
                logToUi("[INFO] Build cancelled.");
                return;
            }
            e.printStackTrace();
            setErrorUi(e.getMessage() != null ? e.getMessage() : "Local APK build/sign failed.");
        }
    }

    private File prepareSourceApkFile(File workDir, String importedApkBase64) throws IOException {
        File outFile = new File(workDir, "source_skeleton.apk");
        if (importedApkBase64 != null && !importedApkBase64.isEmpty()) {
            byte[] bytes = Base64.decode(importedApkBase64, Base64.DEFAULT);
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                fos.write(bytes);
            }
            logToUi("[INFO] Using imported APK (" + bytes.length + " bytes).");
            return outFile;
        }

        try (InputStream is = getAssets().open(SKELETON_ASSET_NAME);
             FileOutputStream fos = new FileOutputStream(outFile)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = is.read(buf)) != -1) {
                fos.write(buf, 0, len);
            }
        }
        logToUi("[INFO] Copied assets/" + SKELETON_ASSET_NAME + " to cache.");
        return outFile;
    }

    private byte[] decodeBase64Image(String iconBase64) {
        if (iconBase64 == null || iconBase64.isEmpty()) return null;
        String clean = iconBase64.contains(",") ? iconBase64.substring(iconBase64.indexOf(",") + 1) : iconBase64;
        try {
            return Base64.decode(clean, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private byte[] buildFinalConfigBytes(String configContent, String startUrl) {
        String cfg = (configContent != null && !configContent.trim().isEmpty())
                ? configContent
                : readDefaultConfigContent();
        if (startUrl != null && !startUrl.isEmpty()) {
            String escapedUrl = startUrl.replace("\\", "\\\\").replace("\"", "\\\"");
            cfg = cfg.replaceAll("(\\bstartURL\\s*:\\s*)([\"'])[^\"']*\\2", "$1\"" + escapedUrl + "\"");
        }
        return cfg.getBytes(StandardCharsets.UTF_8);
    }

    private void updateZipEntries(File inApk, File outApk, byte[] configBytes, byte[] iconBytes) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(inApk)));
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outApk))) {

            byte[] buffer = new byte[8192];
            boolean wroteConfig = false;
            ZipEntry entry;

            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();

                if (name.startsWith("META-INF/") && (
                        name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC")
                )) {
                    zis.closeEntry();
                    continue;
                }

                if ("assets/appConfig.js".equals(name)) {
                    zos.putNextEntry(new ZipEntry("assets/appConfig.js"));
                    zos.write(configBytes);
                    zos.closeEntry();
                    wroteConfig = true;
                    zis.closeEntry();
                    continue;
                }

                if (iconBytes != null && name.startsWith("res/mipmap-") && name.toLowerCase(Locale.US).endsWith(".png")) {
                    zos.putNextEntry(new ZipEntry(name));
                    zos.write(iconBytes);
                    zos.closeEntry();
                    zis.closeEntry();
                    continue;
                }

                zos.putNextEntry(new ZipEntry(name));
                if (!entry.isDirectory()) {
                    int len;
                    while ((len = zis.read(buffer)) != -1) {
                        zos.write(buffer, 0, len);
                    }
                }
                zos.closeEntry();
                zis.closeEntry();
            }

            if (!wroteConfig) {
                zos.putNextEntry(new ZipEntry("assets/appConfig.js"));
                zos.write(configBytes);
                zos.closeEntry();
            }
        }
    }

    private void signApkWithGoogleApksig(File inputApk, File outputApk) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (!keyStore.containsAlias(TEST_KEY_ALIAS)) {
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 25);

            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    TEST_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN)
                    .setCertificateSubject(new X500Principal("CN=SSB Test Signer"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .build();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            kpg.initialize(spec);
            kpg.generateKeyPair();
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(TEST_KEY_ALIAS, null);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(TEST_KEY_ALIAS);

        if (privateKey == null || cert == null) {
            throw new IllegalStateException("Failed to load test key or certificate.");
        }

        ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                "test_signer", privateKey, Collections.singletonList(cert))
                .build();

        new ApkSigner.Builder(Collections.singletonList(signerConfig))
                .setInputApk(inputApk)
                .setOutputApk(outputApk)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build()
                .sign();
    }

    private File getOutputApkFile() {
        File outDir = getExternalFilesDir(null);
        if (outDir != null && !outDir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            outDir.mkdirs();
        }
        return new File(outDir, "output-signed.apk");
    }

    private void promptInstall() {
        File apkFile = getOutputApkFile();
        if (!apkFile.exists()) {
            showAlert("Error", "Signed APK file not found!");
            return;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (!getPackageManager().canRequestPackageInstalls()) {
                showAlert("Permission required", "Enable install unknown apps permission for this app.");
                Uri settingsUri = Uri.parse("package:" + getPackageName());
                Intent settingsIntent = new Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, settingsUri);
                startActivity(settingsIntent);
                return;
            }
        }

        Intent intent = new Intent(Intent.ACTION_VIEW);
        Uri apkUri;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            apkUri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", apkFile);
            intent.setDataAndType(apkUri, "application/vnd.android.package-archive");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } else {
            apkUri = Uri.fromFile(apkFile);
            intent.setDataAndType(apkUri, "application/vnd.android.package-archive");
        }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
    }

    private String readStreamToString(InputStream is) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
    }

    private void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) {
                for (File c : children) {
                    deleteRecursive(c);
                }
            }
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    private void logToUi(String message) {
        mainHandler.post(() -> {
            String escaped = message
                    .replace("\\", "\\\\")
                    .replace("'", "\\'")
                    .replace("\n", "\\n");
            webView.evaluateJavascript("appendLog('" + escaped + "');", null);
        });
    }

    private void setReadyUi() {
        mainHandler.post(() -> webView.evaluateJavascript("setAppReadyForInstall();", null));
    }

    private void setErrorUi(String errorMsg) {
        mainHandler.post(() -> {
            String escaped = errorMsg
                    .replace("\\", "\\\\")
                    .replace("'", "\\'")
                    .replace("\n", "\\n");
            webView.evaluateJavascript("setBuildError('" + escaped + "');", null);
        });
    }

    private void showAlert(String title, String message) {
        mainHandler.post(() -> new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton("OK", null)
                .show());
    }

    public class WebAppInterface {
        Context mContext;

        WebAppInterface(Context c) {
            mContext = c;
        }

        @JavascriptInterface
        public void requestDefaultConfig() {
            executor.execute(() -> sendDefaultConfigToUi());
        }

        @JavascriptInterface
        public void inspectImportedApk(String importedApkBase64) {
            if (importedApkBase64 == null || importedApkBase64.trim().isEmpty()) return;
            executor.execute(() -> {
                try {
                    File importedFile = new File(getCacheDir(), "imported_source.apk");
                    byte[] bytes = Base64.decode(importedApkBase64.trim(), Base64.DEFAULT);
                    try (FileOutputStream fos = new FileOutputStream(importedFile)) {
                        fos.write(bytes);
                    }
                    logToUi("[INFO] Cached imported APK (" + bytes.length + " bytes).");
                } catch (Exception e) {
                    logToUi("[WARN] Failed to cache imported APK: " + e.getMessage());
                }
            });
        }

        @JavascriptInterface
        public void reloadSkeletonMetadata() {
            buildCancelled = true;
            executor.execute(() -> sendDefaultConfigToUi());
        }

        @JavascriptInterface
        public void startCreatingApp(
                String appName,
                String packageName,
                String iconBase64,
                String startUrl,
                String configContent,
                String sdkMin,
                String sdkMax,
                String importedApkBase64
        ) {
            executor.execute(() -> buildLocalApkWithArsclibAndSign(
                    appName != null ? appName.trim() : "",
                    packageName != null ? packageName.trim() : "",
                    iconBase64 != null ? iconBase64.trim() : "",
                    startUrl != null ? startUrl.trim() : "",
                    configContent != null ? configContent : "",
                    sdkMin != null ? sdkMin.trim() : "",
                    sdkMax != null ? sdkMax.trim() : "",
                    importedApkBase64 != null ? importedApkBase64.trim() : ""
            ));
        }

        @JavascriptInterface
        public void installApp() {
            mainHandler.post(() -> promptInstall());
        }

        @JavascriptInterface
        public void closeApp() {
            mainHandler.post(() -> finish());
        }
    }
}
