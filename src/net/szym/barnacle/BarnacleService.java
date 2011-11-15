/*
Step 1. The wifiState can get to == WifiManager.WIFI_STATE_DISBALED

Step 2. Don't need checkUplink() because we don't need 3G from ConnectivityManager.TYPE_MOBILE or ConnetivityManager.TYPE_WIMAX.

Step 3. ?? Don't need app.findIfWan()

Step 4. didn't look at prepareIni
*/

/*
*  This file is part of Barnacle Wifi Tether
*  Copyright (C) 2010 by Szymon Jakubczak
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package net.szym.barnacle;

import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;

import android.app.Notification;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.PowerManager;
import android.util.Log;

/**
* Manages the running process, client list, and log
*/
public class BarnacleService extends android.app.Service {
    final static String TAG = "BarnacleService";
    // messages from the process
    final static int MSG_OUTPUT     = 1;
    final static int MSG_ERROR      = 2;
    // messages from self
    final static int MSG_EXCEPTION  = 3;
    final static int MSG_NETSCHANGE = 4;
    // requests from activities
    final static int MSG_START      = 5;
    final static int MSG_STOP       = 6;
    final static int MSG_ASSOC      = 7;
    final static int MSG_STATS      = 8;
    final static int MSG_FILTER     = 9;
    // app states
    public final static int STATE_STOPPED  = 0;
    public final static int STATE_STARTING = 1;
    public final static int STATE_RUNNING  = 2; // process said OK

    // private state
    private int state = STATE_STOPPED;
    private Process process = null; // the barnacle process
    //private LocalSocket nat_ctrl = null;
    // output monitoring threads
    private Thread[] threads = new Thread[2];
    private PowerManager.WakeLock wakeLock;
    private BroadcastReceiver connectivityReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            mHandler.sendEmptyMessage(MSG_NETSCHANGE);
        }
    };

    // public state
    public final Util.StyledStringBuilder log = new Util.StyledStringBuilder();

    final static int COLOR_ERROR    = 0xffff2222;
    final static int COLOR_LOG      = 0xff888888;//android.R.color.primary_text_dark;
    final static int COLOR_TIME     = 0xffffffff;

    public static class ClientData {
        final String mac;
        final String ip;
        final String hostname;
        boolean allowed;
        ClientData(String m, String i, String h) { mac = m; ip = i; hostname = h; allowed = false; }
        public String toString() { return mac + " " + ip + " " + hostname; }
        public String toNiceString() { return hostname != null ? hostname : mac; }
    }
    public final ArrayList<ClientData> clients = new ArrayList<ClientData>();
    public final Util.TrafficStats stats = new Util.TrafficStats();

    // WARNING: this is not entirely safe
    public static BarnacleService singleton = null;

    // cached for convenience
    private String if_lan = "";
    private Util.MACAddress if_mac = null;
    private BarnacleApp app;
    private WifiManager wifiManager;
    private ConnectivityManager connManager;
    private boolean filteringEnabled = false;
    private Method mStartForeground = null;

    /** public service interface */
    public void startRequest() {
        mHandler.sendEmptyMessage(MSG_START);
    }

    public void assocRequest() {
        mHandler.sendEmptyMessage(MSG_ASSOC);
    }

    public void filterRequest(String mac, boolean allowed) {
        mHandler.obtainMessage(MSG_FILTER, (allowed ? "MACA|" : "MACD|") + mac).sendToTarget();
    }

    public void dmzRequest(String ip) {
        mHandler.obtainMessage(MSG_FILTER, "DMZ|" + ip).sendToTarget();
    }

    public void stopRequest() {
        mHandler.sendEmptyMessage(MSG_STOP);
    }

    public void statsRequest(long delay) {
        Message msg = mHandler.obtainMessage(MSG_STATS);
        mHandler.sendMessageDelayed(msg, delay);
    }

    public int getState() {
        return state;
    }

    public boolean hasFiltering() {
        return filteringEnabled;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        singleton = this;

        wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        connManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);

        try {
            mStartForeground = getClass().getMethod("startForeground", new Class[] {
                    int.class, Notification.class});
        } catch (NoSuchMethodException e) {
            mStartForeground = null;
        }

        state = STATE_STOPPED;
        filteringEnabled = false;

        app = (BarnacleApp)getApplication();
        app.serviceStarted(this);

        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "BarnacleService");
        wakeLock.acquire();

        IntentFilter filter = new IntentFilter();
        filter.addAction(WifiManager.WIFI_STATE_CHANGED_ACTION);
        filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityReceiver, filter);
    }

    @Override
    public void onDestroy() {
        if (state != STATE_STOPPED)
            Log.e(TAG, "service destroyed while running!");
        // ensure we clean up
        stopProcess();
        state = STATE_STOPPED;
        app.processStopped();
        wakeLock.release();

        try {
            unregisterReceiver(connectivityReceiver);
        } catch (Exception e) {
            // ignore
        }

        singleton = null;
        super.onDestroy();
    }

    // our handler
    private final Handler mHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) { handle(msg); }
    };

    private void handle(Message msg) {
        switch (msg.what) {
        case MSG_EXCEPTION:
            if (state == STATE_STOPPED) return;
            Throwable thr = (Throwable)msg.obj;
            log(true, getString(R.string.exception) + " " + thr.getMessage());
            Log.e(TAG, "Exception " + thr.getMessage() + " " + Log.getStackTraceString(thr));
            stopProcess();
            state = STATE_STOPPED;
            break;
        case MSG_ERROR:
            if (state == STATE_STOPPED) return;
            if (process == null) return; // don't kill it again...
            if (msg.obj != null) {
                String line = (String)msg.obj;
                log(true, line); // just dump it and ignore it
                /*if (line.startsWith("dnsmasq: DHCPACK")) {
                    String[] vals = line.split(" +");
                    if (vals.length > 3) {
                        ClientData cd = new ClientData(vals[3], vals[2], vals.length > 4 ? vals[4] : null);
                        clientAdded(cd);
                    }
                }*/
            } else {
                // no message, means process died
                log(true, getString(R.string.unexpected));
                stopProcess();

                if ((state == STATE_STARTING)) {
                    String err = log.toString();
                    if (isRootError(err)) {
                        app.failed(BarnacleApp.ERROR_ROOT);
                    } else if (isSupplicantError(err)) {
                        app.failed(BarnacleApp.ERROR_SUPPLICANT);
                    } else {
                        app.failed(BarnacleApp.ERROR_OTHER);
                    }
                } else {
                    app.failed(BarnacleApp.ERROR_OTHER);
                }
                state = STATE_STOPPED;
            }
            break;
        case MSG_OUTPUT:
            if (state == STATE_STOPPED) return;
            if (process == null) return; // cut the gibberish
            String line = (String)msg.obj;
            if (line == null) {
                // ignore it, wait for MSG_ERROR(null)
                break;
            }
            /*if (line.startsWith("DHCP: ACK")) {
                // DHCP: ACK <MAC> <IP> [<HOSTNAME>]
                String[] vals = line.split(" +");
                ClientData cd = new ClientData(vals[2], vals[3], vals.length > 4 ? vals[4] : null);
                clientAdded(cd);
            } else*/
             if (line.startsWith("WIFI: OK")) {
                // WIFI: OK <IFNAME> <MAC>
                String[] parts = line.split(" +");
                if_lan = parts[2];
                if_mac = Util.MACAddress.parse(parts[3]);
                if (state == STATE_STARTING) {
                    //connectToNat();

                    state = STATE_RUNNING;
                    log(false, getString(R.string.running));
                    clients.clear();
                    stats.init(Util.fetchTrafficData(if_lan));
                    app.processStarted();
                    mHandler.sendEmptyMessage(MSG_ASSOC);
                }
            } else {
                log(false, line);
            }
            break;
        case MSG_START:

            if (state != STATE_STOPPED) return;
            log.clear();
            log(false, getString(R.string.starting));

            if (!app.prepareBinaries()) {
                log(true, getString(R.string.unpackerr));
                state = STATE_STOPPED;
                break;
            }
            state = STATE_STARTING;
            // FALL THROUGH!
        case MSG_NETSCHANGE:
            log(false, "hq. MSG_NETSCHANGE. about to get getWifiState");
            int wifiState = wifiManager.getWifiState();
            log(false, "hq. " + TAG + String.format("NETSCHANGE: %d %d %s", wifiState, state, process == null ? "null" : "proc"));
            Log.e(TAG, String.format("NETSCHANGE: %d %d %s", wifiState, state, process == null ? "null" : "proc"));
            log(false, "hq. " + String.format("wifiState %d =? WifiManager.WIFI_STATE_DISABLED = %d", wifiState, WifiManager.WIFI_STATE_DISABLED));
            if (wifiState == WifiManager.WIFI_STATE_DISABLED) {
                log(false, "hq. INSIDE :) wifi state disabled");
                log(false, String.format(
                    "( (state = %d) ?== (STATE_STARTING = %d) ) && ( (process = %s) ?== null ... && checkUplink:", state, STATE_STARTING, process == null ? "proc_is_null" : "proc_is_not_null"));
                // wifi is good (or lost), we can start now...
                //if ((state == STATE_STARTING) && (process == null) && checkUplink()) {
                // don't need checkUplink()
                if ((state == STATE_STARTING) && (process == null)) {
                    log(false, "hq. in state == STATE STARTING and no proccess and checkuplink :D:D:D");
                    log(false, getString(R.string.dataready));
                    // I guess we don't need WAN
                    /*
                    if (!app.findIfWan()) {
                        log(true, getString(R.string.wanerr));
                        state = STATE_STOPPED;
                        break;
                    }
                    */
                    if (!app.prepareIni()) {
                        log(true, getString(R.string.inierr));
                        state = STATE_STOPPED;
                        break;
                    }
                    log(false, getString(R.string.iniok));
                    log(false, "hq. :):):):):) :D:D:D:D:D:D about to startProcess()");
                    if (!startProcess()) {
                        log(true, getString(R.string.starterr));
                        state = STATE_STOPPED;
                        break;
                    }
                } // if not checkUpLink then we simply wait...
                else {
                    log(true, "either state != STATE_STARTING or process != null");
                }
            } else {
                log(false, "hq. Wifi state Enabled! :( the else before STATE_STARTING");
                if (state == STATE_RUNNING) {
                    // this is super bad, will have to restart!
                    app.updateToast(getString(R.string.conflictwifi), true);
                    log(true, getString(R.string.conflictwifi));
                    log(false, getString(R.string.restarting));
                    stopProcess(); // this tears down wifi
                    wifiManager.setWifiEnabled(false); // this will send MSG_NETSCHANGE
                    // we should wait until wifi is disabled...
                    state = STATE_STARTING;
                } else if (state == STATE_STARTING) {
                    log(false, "hq if state == STATE_STARTING, turn off wifi");
                    if ((wifiState == WifiManager.WIFI_STATE_ENABLED) ||
                        (wifiState == WifiManager.WIFI_STATE_ENABLING)) {
                        app.updateToast(getString(R.string.disablewifi), false);
                        wifiManager.setWifiEnabled(false);
                        log(false, getString(R.string.waitwifi));
                    }
                }
            }
            break;
        case MSG_STOP:
            if (state == STATE_STOPPED) return;
            stopProcess();
            log(false, getString(R.string.stopped));
            state = STATE_STOPPED;
            break;
        case MSG_ASSOC:
            if (state != STATE_RUNNING) return;
            if (tellProcess("WLAN")) {
                app.updateToast(getString(R.string.beaconing), true);
            }
            if (clients.isEmpty() && app.prefs.getBoolean("lan_autoassoc", false)) {
                mHandler.removeMessages(MSG_ASSOC);
                // rebeacon, in 5 seconds
                mHandler.sendEmptyMessageDelayed(MSG_ASSOC, 5000);
            }
            break;
        case MSG_FILTER:
            if (state != STATE_RUNNING) return;
            /*if (tellNat((String)msg.obj)) {
                app.updateToast(getString(R.string.filterupdated), false);
            }*/
            break;
        case MSG_STATS:
            mHandler.removeMessages(MSG_STATS);
            if (state != STATE_RUNNING || if_lan.length() == 0) return;
            stats.update(Util.fetchTrafficData(if_lan));
            break;
        }
        app.updateStatus();
        if (state == STATE_STOPPED)
            app.processStopped();
    }

    protected void log(boolean error, String msg) {
        android.text.format.Time time = new android.text.format.Time();
        time.setToNow();
        Log.i(TAG, "log: " + msg);
        log.append(COLOR_TIME, time.format("%H:%M:%S\t"))
          .append(error ? COLOR_ERROR : COLOR_LOG, msg)
          .append("\n");
    }

    /** Worker Threads */
    private class OutputMonitor implements Runnable {
        private final java.io.BufferedReader br;
        private final int msg;
        public OutputMonitor(int t, java.io.InputStream is) {
            br = Util.toReader(is);
            msg = t;
        }
        public void run() {
            try{
                String line;
                do {
                    line = br.readLine();
                    mHandler.obtainMessage(msg, line).sendToTarget(); // NOTE: the last null is also sent!
                } while(line != null);
            } catch (Exception e) {
                mHandler.obtainMessage(MSG_EXCEPTION, e).sendToTarget();
            }
        }
    }

    private void clientAdded(ClientData cd) {
        boolean firstConnect = true;

        for (int i = 0; i < clients.size(); ++i) {
            ClientData c = clients.get(i);
            if (c.mac.equals(cd.mac)) {
                if (c.ip.equals(cd.ip)) {
                    log(false, String.format(getString(R.string.renewed), cd.toNiceString()));
                    return; // no change
                }
                cd.allowed = c.allowed;
                clients.remove(i); // we'll add it at the end
                firstConnect = false;
                break;
            }
        }
        clients.add(cd);

        //if (nat_ctrl == null)
        //    connectToNat(); // re-attempt to connect

        log(false, String.format(getString(R.string.connected), cd.toNiceString()));
        app.clientAdded(cd);

    }

    /*private boolean checkUplink() {
        log(false, "hq. in checkUplink()");
        if (app.prefs.getBoolean("wan_nowait", false)) {
            return true;
        }
        // 0 = ConnectivityManager.TYPE_MOBILE
        NetworkInfo mobileInfo = connManager.getNetworkInfo(ConnectivityManager.TYPE_MOBILE);
        // 6 = ConnectivityManager.TYPE_WIMAX
        NetworkInfo wimaxInfo = connManager.getNetworkInfo(6);
        
        log(false, String.format("mobileINfor.isConnected?: %s", mobileInfo.isConnected() == true ? "yes_it_is" : "no_its_not"));
        if (wimaxInfo != null){
            log(false, String.format("|| ( wimaxInfo: %s != null, && wimaxInfo.isConnected(): %s)", wimaxInfo == null ? "null" : "not_null",  wimaxInfo.isConnected() == true ? "yes_it_is" : "no_its_not"));
        }else{
            log(false, "|| 0 wimaxInfo is null");
        }
        return (mobileInfo.isConnected() || ((wimaxInfo != null) && wimaxInfo.isConnected()));
    }
    */
    private boolean startProcess() {
        // start the process
        try {
            log(true, "hq==============\nBarnacleService: startProcess()");
            log(false, "hq     pb = new ProcessBuilder");
            ProcessBuilder pb = new ProcessBuilder();
            log(false, "hq     ./File_SCRIPT");
            pb.command("./" + BarnacleApp.FILE_SCRIPT).directory(getFilesDir());
            log(false, "hq     pb.start()");
            // TODO: consider putting brncl.ini in pb.environment() instead of using ./setup
            process = pb.start(); //Runtime.getRuntime().exec(cmd);
            log(false, "hq     new Thread 0 OUTPUT");
            threads[0] = new Thread(new OutputMonitor(MSG_OUTPUT, process.getInputStream()));
            log(false, "hq     new Thread 1 ERROR");
            threads[1] = new Thread(new OutputMonitor(MSG_ERROR, process.getErrorStream()));
            log(false, "hq     threads 0 start");
            threads[0].start();
            log(false, "hq     threads 1 start");
            threads[1].start();
        } catch (Exception e) {
            log(true, "hq     in startProcess exception");
            log(true, String.format(getString(R.string.execerr), BarnacleApp.FILE_SCRIPT));
            Log.e(TAG, "start failed " + e.toString());
            return false;
        }
        return true;
    }

    /*private void connectToNat() {
        nat_ctrl = new LocalSocket();
        for (int i = 0; i < 3; ++i) {
            try {
                nat_ctrl.connect(
                    new LocalSocketAddress(
                        app.natCtrlPath(),
                        LocalSocketAddress.Namespace.FILESYSTEM
                    )
                ); // NOTE: TIMEOUT IS NOT SUPPORTED!
                log(false, getString(R.string.filterok));

                if (app.prefs.getBoolean(getString(R.string.nat_filter), false)) {
                    filteringEnabled = tellNat("FILT|1");
                }
                return;
            } catch (java.io.IOException e) {
                Log.e(TAG, "LocalSocket.connect to '" + app.natCtrlPath() +
                          "' failed: " + e.toString());
            }
            try {
                Thread.sleep(100); // this is so wrong -- service should not halt
            } catch (InterruptedException e) {
                break;
            }
        }
        log(false, getString(R.string.filtererr));
        try {
            nat_ctrl.close();
        } catch (IOException e) {}
        nat_ctrl = null;
    }
    */
    private boolean tellProcess(String msg) {
        if (process != null) {
            try {
                process.getOutputStream().write((msg+"\n").getBytes());
                return true;
            } catch (Exception e) {} // just ignore it
        }
        return false;
    }

    /*
    private boolean tellNat(String msg) {
        if (nat_ctrl != null) {
            Log.d(TAG, "tellNat " + msg);
            try {
                DataOutputStream dos = new DataOutputStream(nat_ctrl.getOutputStream());
                assert msg.length() < 256;
                dos.writeByte(msg.length());
                dos.writeBytes(msg);
                return true;
            } catch (Exception e) {
                log(true, getString(R.string.filtererr));
                nat_ctrl = null;
            }
        }
        return false;
    }
    */

    private void stopProcess() {
        if (process != null) {
            // first, just close the stream
            if (state != STATE_STOPPED) {
                try {
                    process.getOutputStream().close();
                } catch (Exception e) {
                    Log.w(TAG, "Exception while closing process");
                }
            }
            try {
                process.waitFor(); // blocking!
            } catch (InterruptedException e) {
                Log.e(TAG, "");
            }

            try {
                int exit_status = process.exitValue();
                Log.i(TAG, "Process exited with status: " + exit_status);
            } catch (IllegalThreadStateException e) {
                // this is not good
                log(true, getString(R.string.dirtystop));
            }
            process.destroy();
            process = null;
            threads[0].interrupt();
            threads[1].interrupt();
            //nat_ctrl = null;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    /**
    * This is a wrapper around the new startForeground method, using the older
    * APIs if it is not available.
    */
    public void startForegroundCompat(int id, Notification notification) {
        // If we have the new startForeground API, then use it.
        if (mStartForeground != null) {
            try {
                mStartForeground.invoke(this, new Object[] {Integer.valueOf(id), notification});
            } catch (InvocationTargetException e) {
                Log.w(TAG, "Unable to invoke startForeground", e);
            } catch (IllegalAccessException e) {
                Log.w(TAG, "Unable to invoke startForeground", e);
            }
            return;
        }
        // Fall back on the old API.
        setForeground(true);
    }

    public static boolean isSupplicantError(String msg) {
        return msg.contains("supplicant");
    }

    public static boolean isRootError(String msg) {
        return msg.contains("ermission") || msg.contains("su: not found");
    }
}

