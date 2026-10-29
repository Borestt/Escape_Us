const crypto = require('node:crypto');
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('node:path');
const dns = require('node:dns').promises;
const net = require('node:net');

function ehIpPrivado(ip) {
    if (net.isIPv4(ip)) {
        const partes = ip.split('.').map(Number);
        const [a, b] = partes;

        return (
            a === 0 ||
            a === 10 ||
            a === 127 ||
            (a === 169 && b === 254) ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 168) ||
            (a === 100 && b >= 64 && b <= 127) ||
            a >= 224
        );
    }

    if (net.isIPv6(ip)) {
        const endereco = ip.toLowerCase();

        return (
            endereco === '::' ||
            endereco === '::1' ||
            endereco.startsWith('fc') ||
            endereco.startsWith('fd') ||
            endereco.startsWith('fe8') ||
            endereco.startsWith('fe9') ||
            endereco.startsWith('fea') ||
            endereco.startsWith('feb') ||
            endereco.startsWith('::ffff:')
        );
    }

    return true;
}

async function validarUrl(valor) {
    let url;

    try {
        url = new URL(valor);
    } catch {
        throw new Error('Digite uma URL válida, como https://example.com');
    }

    if (!['http:', 'https:'].includes(url.protocol)) {
        throw new Error('Utilize somente URLs HTTP ou HTTPS.');
    }

    if (url.username || url.password) {
        throw new Error('Não inclua credenciais na URL.');
    }

    if (!url.hostname.includes('.') || url.hostname.endsWith('.')) {
        throw new Error('Informe um domínio público válido.');
    }

    const hostname = url.hostname.toLowerCase();

    if (
        hostname === 'localhost' ||
        hostname.endsWith('.localhost') ||
        hostname.endsWith('.local') ||
        net.isIP(hostname)
    ) {
        throw new Error('Endereços locais e IPs diretos não são permitidos.');
    }

    let enderecos;

    try {
        enderecos = await dns.lookup(hostname, { all: true });
    } catch {
        throw new Error('Não foi possível localizar o domínio informado.');
    }

    if (
        enderecos.length === 0 ||
        enderecos.some(item => ehIpPrivado(item.address))
    ) {
        throw new Error('O domínio não resolveu exclusivamente para endereços públicos permitidos.');
    }

    return url;
}

ipcMain.handle('analisar-site', async (evento, valor) => {
    // Aceita solicitações somente da janela local do aplicativo.
    if (!evento.senderFrame?.url.startsWith('file://')) {
        throw new Error('Origem da solicitação não autorizada.');
    }

    if (typeof valor !== 'string' || valor.length > 2048) {
        throw new Error('A URL informada é inválida.');
    }

    const url = await validarUrl(valor);

    let resposta;

    try {
        resposta = await fetch(url, {
            method: 'GET',
            redirect: 'manual',
            signal: AbortSignal.timeout(10000),
            headers: {
                'User-Agent': 'VerificadorSeguranca/1.0'
            }
        });
    } catch (erro) {
        if (erro.name === 'TimeoutError') {
            throw new Error('O site demorou demais para responder.');
        }

        throw new Error(
            'Não foi possível consultar o site. Verifique a URL, a conexão e os redirecionamentos.'
        );
    }

    // Nesta primeira versão, não seguimos redirecionamentos.
    if (resposta.status >= 300 && resposta.status < 400) {
        await resposta.body?.cancel();

        throw new Error(
            'O site redirecionou a requisição. Informe a URL final, preferencialmente com HTTPS.'
        );
    }

    const cabecalhos = Object.fromEntries(resposta.headers.entries());

    await resposta.body?.cancel();

    const csp = cabecalhos['content-security-policy'] || '';
    const xfo = cabecalhos['x-frame-options'] || '';
    const frameAncestors = /(?:^|;)\s*frame-ancestors(?:\s|;|$)/i.test(csp);

    const verificacoes = [
        {
            nome: 'Content-Security-Policy',
            presente: Boolean(csp.trim()),
            valor: csp,
            recomendacao: 'Configure uma política CSP adequada aos recursos e scripts autorizados.'
        },
        {
            nome: 'Strict-Transport-Security',
            presente: url.protocol === 'https:' &&
                Boolean(cabecalhos['strict-transport-security']),
            valor: cabecalhos['strict-transport-security'] || '',
            recomendacao: 'Configure HSTS em HTTPS com uma política adequada à infraestrutura do domínio.'
        },
        {
            nome: 'X-Frame-Options / frame-ancestors',
            presente: ['DENY', 'SAMEORIGIN'].includes(xfo.trim().toUpperCase()) ||
                frameAncestors,
            valor: xfo || (frameAncestors ? 'Proteção encontrada na CSP' : ''),
            recomendacao: 'Configure X-Frame-Options ou a diretiva frame-ancestors da CSP contra enquadramento não autorizado.'
        },
        {
            nome: 'X-Content-Type-Options',
            presente: cabecalhos['x-content-type-options']?.trim().toLowerCase() === 'nosniff',
            valor: cabecalhos['x-content-type-options'] || '',
            recomendacao: 'Configure X-Content-Type-Options: nosniff.'
        }
    ];

    return {
        url: url.href,
        status: resposta.status,
        ok: resposta.ok,
        cabecalhos: cabecalhos,
        verificacoes: verificacoes
    };
});


ipcMain.handle('verificar-senha', async (evento, senha) => {
    if (!evento.senderFrame?.url.startsWith('file://')) {
        throw new Error('Origem da solicitação não autorizada.');
    }

    if (typeof senha !== 'string' || senha.length === 0) {
        throw new Error('Digite uma senha para consultar.');
    }

    if (Buffer.byteLength(senha, 'utf8') > 1024) {
        throw new Error('A senha excede o limite permitido para esta consulta.');
    }

    // 1. Calcula o SHA-1 localmente.
    const hash = crypto
        .createHash('sha1')
        .update(senha, 'utf8')
        .digest('hex')
        .toUpperCase();

    // 2. Separa o prefixo e o sufixo do hash.
    const prefixo = hash.slice(0, 5);
    const sufixoProcurado = hash.slice(5);

    // 3. Consulta a API enviando somente o prefixo.
    let resposta;

    try {
        resposta = await fetch(
            `https://api.pwnedpasswords.com/range/${prefixo}`,
            {
                method: 'GET',
                headers: {
                    'Add-Padding': 'true',
                    'User-Agent': 'VerificadorSeguranca/1.0'
                },
                signal: AbortSignal.timeout(15000)
            }
        );
    } catch {
        throw new Error(
            'Não foi possível acessar a API. Verifique sua conexão e tente novamente.'
        );
    }

    if (!resposta.ok) {
        throw new Error(
            `A API respondeu com o status HTTP ${resposta.status}. Tente novamente.`
        );
    }

    const texto = await resposta.text();

    // 4. Compara os sufixos localmente.
    let ocorrencias = 0;
    let encontrada = false;

    for (const linha of texto.split(/\r?\n/)) {
        const [sufixo, quantidadeTexto] = linha.trim().split(':');

        if (!sufixo || !quantidadeTexto) {
            continue;
        }

        if (sufixo.toUpperCase() === sufixoProcurado) {
            const quantidade = Number(quantidadeTexto);

            if (Number.isSafeInteger(quantidade) && quantidade > 0) {
                encontrada = true;
                ocorrencias = quantidade;
            }

            break;
        }
    }

    // Não devolvemos a senha nem seu hash completo para a interface.
    return {
        encontrada,
        ocorrencias
    };
});

ipcMain.handle('verificar-email', async (evento, email) => {
    if (!evento.senderFrame?.url.startsWith('file://')) {
        throw new Error('Origem da solicitação não autorizada.');
    }

    if (typeof email !== 'string') {
        throw new Error('Informe um endereço de e-mail válido.');
    }

    const endereco = email.trim().toLowerCase();

    if (
        endereco.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(endereco)
    ) {
        throw new Error('Digite um e-mail válido, como usuario@exemplo.com.');
    }

    let resposta;

    try {
        resposta = await fetch(
            'https://api.orelys.io/v1/breaches/check',
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ email: endereco }),
                signal: AbortSignal.timeout(60000)
            }
        );
    } catch (erro) {
        if (erro.name === 'TimeoutError') {
            throw new Error(
                'A consulta demorou mais de 60 segundos. Aguarde antes de tentar novamente.'
            );
        }

        throw new Error(
            'Não foi possível conectar à API de vazamentos. Verifique sua conexão.'
        );
    }

    if (!resposta.ok) {
        if (resposta.status === 429 || resposta.status === 503) {
            const espera = resposta.headers.get('Retry-After');

            throw new Error(
                `A API está ocupada ou atingiu um limite de consultas. Tente novamente mais tarde.${espera ? ` Tempo indicado para espera: ${espera} segundos.` : ''}`
            );
        }

        if (resposta.status === 504) {
            throw new Error(
                'A fonte de dados não respondeu a tempo. Aguarde antes de tentar novamente.'
            );
        }

        throw new Error(`A API respondeu com o status HTTP ${resposta.status}.`);
    }

    let dados;

    try {
        dados = await resposta.json();
    } catch {
        throw new Error('A API retornou uma resposta que não pôde ser interpretada.');
    }

    if (
        typeof dados.found !== 'boolean' ||
        !Array.isArray(dados.breaches) ||
        !Number.isInteger(dados.count) ||
        !Number.isInteger(dados.hidden)
    ) {
        throw new Error('O formato da resposta da API é inesperado.');
    }

    // Devolvemos somente os campos necessários para a interface.
    return {
        encontrado: dados.found,
        quantidade: dados.count,
        ocultos: dados.hidden,
        vazamentos: dados.breaches.map(vazamento => ({
            nome: String(vazamento.name || 'Nome indisponível'),
            data: String(vazamento.breach_date || 'Data não informada'),
            tipos: Array.isArray(vazamento.found_types)
                ? vazamento.found_types.map(tipo => String(tipo))
                : [],
            resumo: String(vazamento.summary || 'Sem descrição disponível'),
            naoVerificado: Boolean(vazamento.unverified)
        }))
    };
});

function criarJanela() {
    const janela = new BrowserWindow({
        width: 1100,
        height: 750,
        minWidth: 800,
        minHeight: 600,
        title: 'Verificador de Segurança',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });

    janela.loadFile('index.html');
}

app.whenReady().then(() => {
    criarJanela();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            criarJanela();
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});
