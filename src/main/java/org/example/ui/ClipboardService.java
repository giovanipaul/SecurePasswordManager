package org.example.ui;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

final class ClipboardService implements AutoCloseable {
    private static final int DEFAULT_CLEAR_SECONDS = 15;
    private final int clearDelaySeconds;
    private final ScheduledExecutorService scheduler;

    ClipboardService() {
        this.clearDelaySeconds = readClearDelay();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(new DaemonThreadFactory());
    }

    boolean copy(String secret) {
        if (secret == null) return false;
        try {
            var systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            systemClipboard.setContents(new StringSelection(secret), null);
            scheduler.schedule(() -> {
                try {
                    systemClipboard.setContents(new StringSelection(""), null);
                } catch (RuntimeException ignored) {
                    // Clipboard availability can change while the app is running.
                }
            }, clearDelaySeconds, TimeUnit.SECONDS);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    int clearDelaySeconds() {
        return clearDelaySeconds;
    }

    private static int readClearDelay() {
        String configured = System.getProperty("passwordmanager.clipboardClearSeconds");
        if (configured == null || configured.isBlank()) return DEFAULT_CLEAR_SECONDS;
        try {
            int seconds = Integer.parseInt(configured);
            return seconds >= 1 && seconds <= 300 ? seconds : DEFAULT_CLEAR_SECONDS;
        } catch (NumberFormatException e) {
            return DEFAULT_CLEAR_SECONDS;
        }
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
    }

    private static final class DaemonThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "password-manager-clipboard-clear");
            thread.setDaemon(true);
            return thread;
        }
    }
}
