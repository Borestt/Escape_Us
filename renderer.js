
const urlSite = document.getElementById('urlSite');
const email = document.getElementById('email');
const senha = document.getElementById('senha');

const resultadoSite = document.getElementById('resultadoSite');
const resultadoEmail = document.getElementById('resultadoEmail');
const resultadoSenha = document.getElementById('resultadoSenha');

document.getElementById('analisarSite').addEventListener('click', async () => {
    const url = urlSite.value.trim();

    if (!url) {
        resultadoSite.textContent = 'Digite a URL de um site.';
        return;
    }

    resultadoSite.textContent = 'Consultando o site...';

    try {
        const resultado = await window.segurancaAPI.analisarSite(url);

        resultadoSite.replaceChildren();

        const titulo = document.createElement('h3');
        titulo.textContent = 'Resultado da análise';
        resultadoSite.appendChild(titulo);

        const endereco = document.createElement('p');
        endereco.textContent = `URL: ${resultado.url}`;
        resultadoSite.appendChild(endereco);

        const status = document.createElement('p');
        status.textContent = `Status HTTP: ${resultado.status}`;
        resultadoSite.appendChild(status);

        const resumo = document.createElement('p');
        const encontrados = resultado.verificacoes.filter(item => item.presente).length;

        resumo.textContent =
            `Proteções encontradas: ${encontrados} de ${resultado.verificacoes.length}`;
        resultadoSite.appendChild(resumo);

        resultado.verificacoes.forEach(item => {
            const bloco = document.createElement('div');
            bloco.style.marginTop = '16px';

            const nome = document.createElement('strong');
            nome.textContent = `${item.presente ? '[ENCONTRADO]' : '[AUSENTE]'} ${item.nome}`;
            bloco.appendChild(nome);

            const valor = document.createElement('p');
            valor.textContent = item.valor
                ? `Valor recebido: ${item.valor}`
                : 'Nenhum valor reconhecido foi encontrado.';
            bloco.appendChild(valor);

            if (!item.presente) {
                const recomendacao = document.createElement('p');
                recomendacao.textContent = `Recomendação: ${item.recomendacao}`;
                bloco.appendChild(recomendacao);
            }

            resultadoSite.appendChild(bloco);
        });

        const tituloCabecalhos = document.createElement('h3');
        tituloCabecalhos.textContent = 'Cabeçalhos recebidos';
        resultadoSite.appendChild(tituloCabecalhos);

        const lista = document.createElement('ul');

        Object.entries(resultado.cabecalhos).forEach(([nome, valor]) => {
            const item = document.createElement('li');
            item.textContent = `${nome}: ${valor}`;
            lista.appendChild(item);
        });

        resultadoSite.appendChild(lista);

    } catch (erro) {
        resultadoSite.textContent = `Falha na análise: ${erro.message}`;
    }
});


document.getElementById('verificarEmail').addEventListener('click', async () => {
    const endereco = email.value.trim();

    if (!endereco) {
        resultadoEmail.textContent = 'Digite um endereço de e-mail.';
        return;
    }

    resultadoEmail.textContent =
        'Consultando os registros conhecidos de vazamentos...';

    try {
        const resultado = await window.segurancaAPI.verificarEmail(endereco);

        resultadoEmail.replaceChildren();

        const titulo = document.createElement('h3');

        titulo.textContent = resultado.encontrado
            ? 'E-mail encontrado em vazamentos conhecidos'
            : 'Nenhuma correspondência encontrada';

        resultadoEmail.appendChild(titulo);

        if (!resultado.encontrado) {
            const mensagem = document.createElement('p');

            mensagem.textContent =
                'O endereço não foi encontrado nos registros consultados. Isso não garante que ele nunca tenha sido exposto.';

            resultadoEmail.appendChild(mensagem);
            return;
        }

        const resumo = document.createElement('p');

        resumo.textContent =
            `Vazamentos identificados publicamente: ${resultado.quantidade}. ` +
            `Vazamentos sensíveis não identificados pelo nome: ${resultado.ocultos}.`;

        resultadoEmail.appendChild(resumo);

        if (resultado.ocultos > 0) {
            const aviso = document.createElement('p');

            aviso.textContent =
                'Existem registros sensíveis adicionais que não podem ser identificados individualmente nesta consulta.';

            resultadoEmail.appendChild(aviso);
        }

        resultado.vazamentos.forEach(vazamento => {
            const cartao = document.createElement('div');

            cartao.style.marginTop = '18px';
            cartao.style.padding = '14px';
            cartao.style.border = '1px solid #42536b';
            cartao.style.borderRadius = '8px';

            const nome = document.createElement('h4');
            nome.textContent = vazamento.nome;
            cartao.appendChild(nome);

            const data = document.createElement('p');
            data.textContent = `Data do vazamento: ${vazamento.data}`;
            cartao.appendChild(data);

            const tipos = document.createElement('p');
            tipos.textContent =
                `Tipos de dados associados: ${
                    vazamento.tipos.length
                        ? vazamento.tipos.join(', ')
                        : 'Não informados'
                }`;

            cartao.appendChild(tipos);

            if (vazamento.resumo) {
                const descricao = document.createElement('p');
                descricao.textContent = vazamento.resumo;
                cartao.appendChild(descricao);
            }

            if (vazamento.naoVerificado) {
                const avisoVerificacao = document.createElement('p');
                avisoVerificacao.textContent =
                    'A informação deste vazamento ainda não foi verificada pelo serviço.';
                cartao.appendChild(avisoVerificacao);
            }

            resultadoEmail.appendChild(cartao);
        });

        const recomendacao = document.createElement('p');

        recomendacao.style.marginTop = '20px';
        recomendacao.textContent =
            'Recomendação: altere as senhas relacionadas aos serviços afetados, ' +
            'não reutilize senhas e ative a autenticação multifator sempre que possível.';

        resultadoEmail.appendChild(recomendacao);

    } catch (erro) {
        resultadoEmail.textContent = `Falha na consulta: ${erro.message}`;
    }
});

document.getElementById('verificarSenha').addEventListener('click', async () => {
    const valorSenha = senha.value;

    if (!valorSenha) {
        resultadoSenha.textContent = 'Digite uma senha para verificar.';
        return;
    }

    resultadoSenha.textContent = 'Consultando a base de senhas expostas...';

    // Evita manter o campo preenchido após iniciar a consulta.
    senha.value = '';

    try {
        const resultado = await window.segurancaAPI.verificarSenha(valorSenha);

        if (resultado.encontrada) {
            resultadoSenha.replaceChildren();

            const titulo = document.createElement('strong');
            titulo.textContent = 'Senha encontrada na base de vazamentos.';
            resultadoSenha.appendChild(titulo);

            const detalhe = document.createElement('p');
            detalhe.textContent =
                `Quantidade de ocorrências registrada: ${resultado.ocorrencias.toLocaleString('pt-BR')}.`;
            resultadoSenha.appendChild(detalhe);

            const recomendacao = document.createElement('p');
            recomendacao.textContent =
                'Recomendação: não utilize essa senha. Se ela estiver em uso em alguma conta, substitua-a por uma senha única.';
            resultadoSenha.appendChild(recomendacao);
        } else {
            resultadoSenha.textContent =
                'Nenhuma ocorrência correspondente foi encontrada na base consultada. Isso não garante que a senha nunca tenha sido exposta.';
        }
    } catch (erro) {
        resultadoSenha.textContent = `Falha na consulta: ${erro.message}`;
    }
});
