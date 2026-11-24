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
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;

import com.android.apksig.ApkSigner;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class MainActivity extends AppCompatActivity {

    private static final int FILE_CHOOSER_RESULT_CODE = 1;
    private static final String SKELETON_ASSET_NAME = "skeleton.apk";
    private static final String KEY_FILE_NAME = "ssb_signer_key.pk8";
    private static final String CERT_FILE_NAME = "ssb_signer_cert.der";

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
                executor.execute(() -> {
                    sendDefaultConfigToUi();
                    sendSkeletonPackageLengthToUi(null);
                });
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

    private void sendSkeletonPackageLengthToUi(File customApkFile) {
        try {
            String detectedPkg = extractPackageNameFromApk(customApkFile);
            if (detectedPkg != null && !detectedPkg.isEmpty()) {
                String encodedPkg = Base64.encodeToString(detectedPkg.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
                mainHandler.post(() -> webView.evaluateJavascript(
                        "setApkMetadata('', decodeURIComponent(escape(atob('" + encodedPkg + "'))));",
                        null
                ));
            }
        } catch (Exception ignored) {
        }
    }

    private String extractPackageNameFromApk(File customApkFile) throws IOException {
        byte[] manifestBytes = readManifestBytesFromApk(customApkFile);
        if (manifestBytes == null || manifestBytes.length == 0) return null;

        String[] candidates = new String[]{
                new String(manifestBytes, StandardCharsets.UTF_16LE),
                new String(manifestBytes, StandardCharsets.UTF_8)
        };

        for (String text : candidates) {
            Matcher mPerm = Pattern.compile("([a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)+)\\.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
                    .matcher(text);
            if (mPerm.find()) {
                return mPerm.group(1);
            }

            Matcher mAuth = Pattern.compile("([a-z][a-z0-9_]*(?:\\.[a-z][a-z0-9_]*)+)\\.androidx-startup")
                    .matcher(text);
            if (mAuth.find()) {
                return mAuth.group(1);
            }
        }
        return null;
    }

    private String detectCurrentLabel(byte[] manifestBytes) {
        if (manifestBytes == null || manifestBytes.length == 0) return null;
        String utf16 = new String(manifestBytes, StandardCharsets.UTF_16LE);
        if (utf16.contains("LFM")) {
            return "LFM";
        }
        String utf8 = new String(manifestBytes, StandardCharsets.UTF_8);
        if (utf8.contains("LFM")) {
            return "LFM";
        }
        return null;
    }

    private byte[] readManifestBytesFromApk(File customApkFile) throws IOException {
        if (customApkFile != null && customApkFile.exists()) {
            try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(customApkFile)))) {
                return readManifestEntry(zis);
            }
        } else {
            try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(getAssets().open(SKELETON_ASSET_NAME)))) {
                return readManifestEntry(zis);
            }
        }
    }

    private byte[] readManifestEntry(ZipInputStream zis) throws IOException {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            if ("AndroidManifest.xml".equals(entry.getName())) {
                byte[] data = readStreamToBytes(zis);
                zis.closeEntry();
                return data;
            }
            zis.closeEntry();
        }
        return null;
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
            File rawPackagedApk = new File(workDir, "raw_packaged.apk");
            File signedOutApk = getOutputApkFile();

            String oldPackage = extractPackageNameFromApk(sourceApk);
            byte[] originalManifest = readManifestBytesFromApk(sourceApk);
            String currentLabel = detectCurrentLabel(originalManifest);

            if (appName != null && !appName.isEmpty() && currentLabel != null) {
                if (appName.length() != currentLabel.length()) {
                    logToUi("[WARN] Label '" + currentLabel + "' has " + currentLabel.length()
                            + " chars, but entered name '" + appName + "' has " + appName.length()
                            + " chars — binary string pool cannot change byte length in-place.");
                }
            }

            if (buildCancelled) return;

            byte[] iconBytes = decodeBase64Image(iconBase64);
            byte[] configBytes = buildFinalConfigBytes(configContent, startUrl);

            logToUi("[INFO] Updating AndroidManifest, resources.arsc, assets/appConfig.js and icons..");
            updateZipEntries(sourceApk, rawPackagedApk, configBytes, iconBytes, oldPackage, packageName, currentLabel, appName);

            if (buildCancelled) return;

            logToUi("[INFO] Signing APK with Google ApkSigner..");
            signApkWithGoogleApksig(rawPackagedApk, signedOutApk);

            logToUi("[SUCCESS] Signed APK ready: " + signedOutApk.getAbsolutePath());
            setReadyUi();
        } catch (Exception e) {
            if (buildCancelled) {
                logToUi("[INFO] Build cancelled.");
                return;
            }
            e.printStackTrace();
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            setErrorUi(msg);
        }
    }

    private byte[] patchBinaryManifestFixedLength(
            byte[] manifestBytes,
            String oldPkg,
            String newPkg,
            String oldLabel,
            String newLabel
    ) {
        if (manifestBytes == null) return null;
        byte[] out = manifestBytes.clone();

        if (oldPkg != null && newPkg != null && !oldPkg.isEmpty() && !newPkg.isEmpty() && !oldPkg.equals(newPkg)) {
            String paddedNewPkg = padPackageToExactLength(newPkg, oldPkg.length());
            replaceStringBothEncodings(out, oldPkg, paddedNewPkg);

            String[] suffixes = new String[]{
                    ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
                    ".androidx-startup"
            };
            for (String suffix : suffixes) {
                replaceStringBothEncodings(out, oldPkg + suffix, paddedNewPkg + suffix);
            }

            replaceStringBothEncodings(out, paddedNewPkg + ".MainActivity", oldPkg + ".MainActivity");
            replaceStringBothEncodings(out, paddedNewPkg + ".MediaService", oldPkg + ".MediaService");
        }

        if (oldLabel != null && newLabel != null && !oldLabel.isEmpty() && !newLabel.isEmpty()) {
            if (oldLabel.length() == newLabel.length()) {
                int replacedCount = replaceStringBothEncodings(out, oldLabel, newLabel);
                logToUi("[INFO] Manifest label '" + oldLabel + "' -> '" + newLabel + "' replaced (" + replacedCount + " matches).");
            } else {
                logToUi("[WARN] Label length mismatch: '" + oldLabel + "' (" + oldLabel.length()
                        + ") vs '" + newLabel + "' (" + newLabel.length() + ").");
            }
        }

        return out;
    }

    private byte[] patchBinaryStringPoolFixedLength(byte[] rawBytes, String oldText, String newText) {
        if (rawBytes == null || oldText == null || newText == null
                || oldText.isEmpty() || newText.isEmpty() || oldText.equals(newText)) {
            return rawBytes;
        }
        if (oldText.length() != newText.length()) {
            return rawBytes;
        }
        byte[] out = rawBytes.clone();
        int count = replaceStringBothEncodings(out, oldText, newText);
        if (count > 0) {
            logToUi("[INFO] resources.arsc label '" + oldText + "' -> '" + newText + "' replaced (" + count + " matches).");
        }
        return out;
    }

    private String padPackageToExactLength(String pkg, int targetLen) {
        if (pkg.length() == targetLen) return pkg;
        if (pkg.length() > targetLen) return pkg.substring(0, targetLen);

        int missing = targetLen - pkg.length();
        StringBuilder pad = new StringBuilder();
        for (int i = 0; i < missing; i++) {
            pad.append('a');
        }

        int lastDot = pkg.lastIndexOf('.');
        if (lastDot > 0 && lastDot < pkg.length() - 1) {
            return pkg.substring(0, lastDot) + pad + pkg.substring(lastDot);
        }
        return pkg + pad;
    }

    private int replaceStringBothEncodings(byte[] data, String oldStr, String newStr) {
        if (oldStr.length() != newStr.length()) return 0;
        int total = 0;

        byte[] oldUtf16 = oldStr.getBytes(StandardCharsets.UTF_16LE);
        byte[] newUtf16 = newStr.getBytes(StandardCharsets.UTF_16LE);
        if (oldUtf16.length == newUtf16.length) {
            total += replaceByteSequence(data, oldUtf16, newUtf16);
        }

        byte[] oldUtf8 = oldStr.getBytes(StandardCharsets.UTF_8);
        byte[] newUtf8 = newStr.getBytes(StandardCharsets.UTF_8);
        if (oldUtf8.length == newUtf8.length) {
            total += replaceByteSequence(data, oldUtf8, newUtf8);
        }
        return total;
    }

    private int replaceByteSequence(byte[] data, byte[] target, byte[] replacement) {
        if (target.length == 0 || target.length != replacement.length || data.length < target.length) {
            return 0;
        }
        int count = 0;
        for (int i = 0; i <= data.length - target.length; i++) {
            boolean match = true;
            for (int j = 0; j < target.length; j++) {
                if (data[i + j] != target[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                System.arraycopy(replacement, 0, data, i, replacement.length);
                count++;
                i += target.length - 1;
            }
        }
        return count;
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

    private void updateZipEntries(
            File inApk,
            File outApk,
            byte[] configBytes,
            byte[] iconBytes,
            String oldPkg,
            String newPkg,
            String oldLabel,
            String newLabel
    ) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(inApk)));
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outApk))) {

            boolean wroteConfig = false;
            ZipEntry entry;

            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                String lower = name.toLowerCase(Locale.US);

                if (name.startsWith("META-INF/") && (
                        lower.endsWith(".sf") || lower.endsWith(".rsa") || lower.endsWith(".dsa") || lower.endsWith(".ec")
                )) {
                    zis.closeEntry();
                    continue;
                }

                if (entry.isDirectory()) {
                    zos.putNextEntry(new ZipEntry(name));
                    zos.closeEntry();
                    zis.closeEntry();
                    continue;
                }

                byte[] entryBytes = readStreamToBytes(zis);

                if ("AndroidManifest.xml".equals(name)) {
                    entryBytes = patchBinaryManifestFixedLength(entryBytes, oldPkg, newPkg, oldLabel, newLabel);
                }

                if ("resources.arsc".equals(name)) {
                    entryBytes = patchBinaryStringPoolFixedLength(entryBytes, oldLabel, newLabel);
                }

                if ("assets/appConfig.js".equals(name)) {
                    writeEntryWithMethod(zos, name, configBytes, ZipEntry.DEFLATED);
                    wroteConfig = true;
                    zis.closeEntry();
                    continue;
                }

                boolean isMipmapPng = name.startsWith("res/mipmap-") && lower.endsWith(".png");
                boolean isTargetDrawablePng = name.startsWith("res/drawable")
                        && lower.endsWith(".png")
                        && (lower.contains("/logo") || lower.contains("/back"));

                if (iconBytes != null && (isMipmapPng || isTargetDrawablePng)) {
                    int method = (entry.getMethod() == ZipEntry.STORED) ? ZipEntry.STORED : ZipEntry.DEFLATED;
                    writeEntryWithMethod(zos, name, iconBytes, method);
                    zis.closeEntry();
                    continue;
                }

                int method = (entry.getMethod() == ZipEntry.STORED || "resources.arsc".equals(name) || lower.endsWith(".so"))
                        ? ZipEntry.STORED
                        : ZipEntry.DEFLATED;
                writeEntryWithMethod(zos, name, entryBytes, method);
                zis.closeEntry();
            }

            if (!wroteConfig) {
                writeEntryWithMethod(zos, "assets/appConfig.js", configBytes, ZipEntry.DEFLATED);
            }
        }
    }

    private void writeEntryWithMethod(ZipOutputStream zos, String name, byte[] data, int method) throws IOException {
        ZipEntry outEntry = new ZipEntry(name);
        if (method == ZipEntry.STORED) {
            CRC32 crc = new CRC32();
            crc.update(data);
            outEntry.setMethod(ZipEntry.STORED);
            outEntry.setSize(data.length);
            outEntry.setCompressedSize(data.length);
            outEntry.setCrc(crc.getValue());
        } else {
            outEntry.setMethod(ZipEntry.DEFLATED);
        }
        zos.putNextEntry(outEntry);
        zos.write(data);
        zos.closeEntry();
    }

    private void signApkWithGoogleApksig(File inputApk, File outputApk) throws Exception {
        SignerCredentials creds = getOrCreateSignerCredentials();

        ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder(
                "ssb_signer", creds.privateKey, Collections.singletonList(creds.certificate))
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

    private static class SignerCredentials {
        final PrivateKey privateKey;
        final X509Certificate certificate;

        SignerCredentials(PrivateKey privateKey, X509Certificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }
    }

    private SignerCredentials getOrCreateSignerCredentials() throws Exception {
        File keyFile = new File(getFilesDir(), KEY_FILE_NAME);
        File certFile = new File(getFilesDir(), CERT_FILE_NAME);

        if (keyFile.exists() && certFile.exists()) {
            try {
                byte[] keyBytes = readStreamToBytes(new FileInputStream(keyFile));
                byte[] certBytes = readStreamToBytes(new FileInputStream(certFile));
                PrivateKey privateKey = KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
                X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(certBytes));
                cert.checkValidity(new Date());
                return new SignerCredentials(privateKey, cert);
            } catch (Exception ignored) {
                //noinspection ResultOfMethodCallIgnored
                keyFile.delete();
                //noinspection ResultOfMethodCallIgnored
                certFile.delete();
            }
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        X509Certificate cert = generateSelfSignedCert(keyPair);

        try (FileOutputStream fos = new FileOutputStream(keyFile)) {
            fos.write(keyPair.getPrivate().getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream(certFile)) {
            fos.write(cert.getEncoded());
        }

        return new SignerCredentials(keyPair.getPrivate(), cert);
    }

    private X509Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception {
        long nowMs = System.currentTimeMillis();
        Date notBefore = new Date(nowMs - 24L * 60 * 60 * 1000);
        Date notAfter = new Date(nowMs + 10L * 365 * 24 * 60 * 60 * 1000);
        BigInteger serial = BigInteger.valueOf(Math.abs(nowMs));

        byte[] sigAlgId = derSequence(
                derOid(new int[]{1, 2, 840, 113549, 1, 1, 11}),
                derNull()
        );
        byte[] cnOid = derOid(new int[]{2, 5, 4, 3});
        byte[] name = derSequence(derSet(derSequence(cnOid, derUtf8String("SSB Local Signer"))));
        byte[] validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter));
        byte[] subjectPublicKeyInfo = keyPair.getPublic().getEncoded();
        byte[] version = derContextTag(0, derInteger(BigInteger.valueOf(2)));

        byte[] tbsCertificate = derSequence(
                version,
                derInteger(serial),
                sigAlgId,
                name,
                validity,
                name,
                subjectPublicKeyInfo
        );

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(tbsCertificate);
        byte[] signatureBytes = sig.sign();

        byte[] certDer = derSequence(
                tbsCertificate,
                sigAlgId,
                derBitString(signatureBytes)
        );

        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static byte[] derSequence(byte[]... items) throws IOException {
        return derWrap(0x30, concatBytes(items));
    }

    private static byte[] derSet(byte[]... items) throws IOException {
        return derWrap(0x31, concatBytes(items));
    }

    private static byte[] derContextTag(int tagNumber, byte[] content) throws IOException {
        return derWrap(0xA0 | (tagNumber & 0x1F), content);
    }

    private static byte[] derNull() {
        return new byte[]{0x05, 0x00};
    }

    private static byte[] derInteger(BigInteger val) throws IOException {
        return derWrap(0x02, val.toByteArray());
    }

    private static byte[] derUtf8String(String s) throws IOException {
        return derWrap(0x0C, s.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] derUtcTime(Date date) throws IOException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return derWrap(0x17, sdf.format(date).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] derBitString(byte[] data) throws IOException {
        byte[] withUnusedBits = new byte[data.length + 1];
        withUnusedBits[0] = 0x00;
        System.arraycopy(data, 0, withUnusedBits, 1, data.length);
        return derWrap(0x03, withUnusedBits);
    }

    private static byte[] derOid(int[] arcs) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(arcs[0] * 40 + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            writeBase128(out, arcs[i]);
        }
        return derWrap(0x06, out.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, int value) {
        if (value < 128) {
            out.write(value);
            return;
        }
        byte[] tmp = new byte[5];
        int idx = tmp.length - 1;
        tmp[idx] = (byte) (value & 0x7F);
        value >>>= 7;
        while (value > 0) {
            idx--;
            tmp[idx] = (byte) (0x80 | (value & 0x7F));
            value >>>= 7;
        }
        out.write(tmp, idx, tmp.length - idx);
    }

    private static byte[] derWrap(int tag, byte[] content) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int len = content.length;
        if (len < 128) {
            out.write(len);
        } else {
            byte[] lenBytes = new byte[4];
            int pos = 3;
            int temp = len;
            while (temp > 0) {
                lenBytes[pos--] = (byte) (temp & 0xFF);
                temp >>>= 8;
            }
            int numOctets = 3 - pos;
            out.write(0x80 | numOctets);
            out.write(lenBytes, pos + 1, numOctets);
        }
        out.write(content);
        return out.toByteArray();
    }

    private static byte[] concatBytes(byte[]... arrays) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] a : arrays) {
            if (a != null) out.write(a);
        }
        return out.toByteArray();
    }

    private byte[] readStreamToBytes(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int len;
        while ((len = in.read(buf)) != -1) {
            out.write(buf, 0, len);
        }
        return out.toByteArray();
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
            executor.execute(() -> {
                sendDefaultConfigToUi();
                sendSkeletonPackageLengthToUi(null);
            });
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
                    sendSkeletonPackageLengthToUi(importedFile);
                } catch (Exception e) {
                    logToUi("[WARN] Failed to cache imported APK: " + e.getMessage());
                }
            });
        }

        @JavascriptInterface
        public void reloadSkeletonMetadata() {
            buildCancelled = true;
            executor.execute(() -> {
                sendDefaultConfigToUi();
                sendSkeletonPackageLengthToUi(null);
            });
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
