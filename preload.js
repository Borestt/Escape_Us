const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('segurancaAPI', {
    analisarSite: (url) =>
        ipcRenderer.invoke('analisar-site', url),

    verificarSenha: (senha) =>
        ipcRenderer.invoke('verificar-senha', senha),

    verificarEmail: (email) =>
        ipcRenderer.invoke('verificar-email', email)
});
