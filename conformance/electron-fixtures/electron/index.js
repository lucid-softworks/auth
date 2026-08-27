const noop = () => {};
const oracle = () => globalThis.__betterAuthElectronOracle;

export const app = {
  getName: () => "oracle",
  getPath: () => "/tmp/oracle",
  getVersion: () => "1.0.0",
  on: noop,
  quit: noop,
  requestSingleInstanceLock: () => true,
  setAsDefaultProtocolClient: () => true,
  userAgentFallback: "electron-oracle",
  whenReady: () => Promise.resolve(),
};
export const contextBridge = {
  exposeInMainWorld: (name, value) => oracle()?.exposed.set(name, value),
};
export const ipcMain = {
  handle: (name, handler) => oracle()?.handlers.set(name, handler),
};
export const ipcRenderer = {
  invoke: async (...args) => oracle()?.invocations.push(args),
  off: noop,
  on: (name) => oracle()?.listeners.push(name),
};
export const net = { fetch: globalThis.fetch };
export const protocol = { handle: noop, registerSchemesAsPrivileged: noop };
export const safeStorage = {
  decryptString: (value) => {
    oracle()?.decryptions.push(value);
    return value.toString();
  },
  encryptString: (value) => {
    oracle()?.encryptions.push(value);
    return Buffer.from(value);
  },
  isEncryptionAvailable: () => oracle()?.storageAvailable ?? true,
};
export const session = { defaultSession: { webRequest: { onHeadersReceived: noop } } };
export const shell = {
  openExternal: async (...args) => oracle()?.opened.push(args),
};
export const webContents = { getFocusedWebContents: () => null };
export const BrowserWindow = { getAllWindows: () => [] };

export default {
  app,
  BrowserWindow,
  contextBridge,
  ipcMain,
  ipcRenderer,
  net,
  protocol,
  safeStorage,
  session,
  shell,
  webContents,
};
