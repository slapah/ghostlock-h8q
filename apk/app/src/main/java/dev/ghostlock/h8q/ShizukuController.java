package dev.ghostlock.h8q;

import android.content.pm.PackageManager;
import android.os.ParcelFileDescriptor;

import java.io.InputStream;
import java.io.OutputStream;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;

/**
 * Thin wrapper over Shizuku that hands back a shell-uid (2000) process — the
 * same security context adb shell provides. The exploit needs it because an
 * ordinary app uid is confined by SELinux away from /data/local/tmp and cannot
 * launch the LD_PRELOAD payload. Modelled on BuSung-dev/Root-My-Galaxy.
 */
final class ShizukuController {

    static final int PERMISSION_REQUEST_CODE = 0x5352;

    private ShizukuController() {
    }

    static boolean isRunning() {
        try {
            return Shizuku.pingBinder();
        } catch (Throwable t) {
            return false;
        }
    }

    static boolean isGranted() {
        try {
            return isRunning()
                    && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Spawn a process in the Shizuku (shell) context. */
    static Process exec(String[] cmd, String[] env, String dir) throws Exception {
        android.os.IBinder binder = Shizuku.getBinder();
        if (binder == null) {
            throw new IllegalStateException("Shizuku binder is not available");
        }
        IShizukuService svc = IShizukuService.Stub.asInterface(binder);
        return new RemoteProcess(svc.newProcess(cmd, env, dir));
    }

    /** Stream an app asset to a shell-owned path, then chmod it. */
    static void writeFile(String remotePath, String mode, InputStream source) throws Exception {
        Process p = exec(new String[]{
                "sh", "-c", "cat > '" + remotePath + "' && chmod " + mode + " '" + remotePath + "'"
        }, null, null);
        int code;
        try (OutputStream out = p.getOutputStream()) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = source.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            out.flush();
        } finally {
            source.close();
        }
        code = p.waitFor();
        if (code != 0) {
            throw new IllegalStateException("Failed to stage " + remotePath + " (exit " + code + ")");
        }
    }

    private static final class RemoteProcess extends Process {
        private final IRemoteProcess remote;
        private InputStream in;
        private OutputStream out;
        private InputStream err;

        RemoteProcess(IRemoteProcess remote) {
            this.remote = remote;
        }

        @Override
        public synchronized InputStream getInputStream() {
            if (in == null) {
                try {
                    in = new ParcelFileDescriptor.AutoCloseInputStream(remote.getInputStream());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            return in;
        }

        @Override
        public synchronized OutputStream getOutputStream() {
            if (out == null) {
                try {
                    out = new ParcelFileDescriptor.AutoCloseOutputStream(remote.getOutputStream());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            return out;
        }

        @Override
        public synchronized InputStream getErrorStream() {
            if (err == null) {
                try {
                    err = new ParcelFileDescriptor.AutoCloseInputStream(remote.getErrorStream());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            return err;
        }

        @Override
        public int waitFor() throws InterruptedException {
            try {
                return remote.waitFor();
            } catch (Exception e) {
                throw new InterruptedException(e.getMessage());
            }
        }

        @Override
        public int exitValue() {
            try {
                return remote.exitValue();
            } catch (Exception e) {
                throw new IllegalThreadStateException(e.getMessage());
            }
        }

        @Override
        public void destroy() {
            try {
                remote.destroy();
            } catch (Exception ignored) {
            }
        }
    }
}
