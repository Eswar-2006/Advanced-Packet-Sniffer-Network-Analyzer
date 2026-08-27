const { app, BrowserWindow, shell, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow = null;
let serverProcess = null;
const PORT = process.env.PORT || 3000;

function startServer() {
  return new Promise((resolve, reject) => {
    // In production, we run the bundled server.cjs, in dev we run server.ts using tsx
    const isDev = !app.isPackaged;
    const serverScript = isDev
      ? path.join(__dirname, '..', 'server.ts')
      : path.join(__dirname, '..', 'dist', 'server.cjs');

    const cmd = isDev ? (process.platform === 'win32' ? 'npx.cmd' : 'npx') : 'node';
    const args = isDev ? ['tsx', serverScript] : [serverScript];

    console.log(`[ELECTRON] Spawning backend process: ${cmd} ${args.join(' ')}`);

    serverProcess = spawn(cmd, args, {
      env: { ...process.env, PORT: PORT.toString(), IS_ELECTRON: 'true' },
      stdio: ['inherit', 'pipe', 'pipe']
    });

    let serverReady = false;

    serverProcess.stdout.on('data', (data) => {
      const output = data.toString();
      console.log(`[SERVER]: ${output.trim()}`);
      if (!serverReady && (output.includes('http://localhost') || output.includes('running on port'))) {
        serverReady = true;
        resolve();
      }
    });

    serverProcess.stderr.on('data', (data) => {
      console.error(`[SERVER ERR]: ${data.toString().trim()}`);
    });

    serverProcess.on('error', (err) => {
      console.error('[ELECTRON] Failed to start backend server process:', err);
      reject(err);
    });

    // Fallback timer if stdout doesn't match specific line
    setTimeout(() => {
      if (!serverReady) {
        serverReady = true;
        resolve();
      }
    }, 3000);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: 'Sentinel Analytica - Enterprise Packet Sniffer & Traffic Analyzer',
    backgroundColor: '#030712',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: false
    },
    autoHideMenuBar: true
  });

  const appUrl = `http://localhost:${PORT}`;
  console.log(`[ELECTRON] Loading application URL: ${appUrl}`);
  mainWindow.loadURL(appUrl);

  // Open external links in default OS browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  try {
    await startServer();
    createWindow();
  } catch (err) {
    console.error('[ELECTRON] App initialization error:', err);
    createWindow();
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (serverProcess) {
    serverProcess.kill();
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('will-quit', () => {
  if (serverProcess) {
    serverProcess.kill();
  }
});
