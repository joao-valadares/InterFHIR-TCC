# Reprodução para a banca

Este protocolo executa o InterFHIR a partir dos arquivos versionados. Não depende de `.local`, certificados, `node_modules`, bancos ou artefatos copiados da máquina do autor. O laboratório gera identidades e dados sintéticos próprios.

## O que significa obter o mesmo resultado

O critério é a equivalência de comportamento: aprovação de todos os testes selecionados e dos 22 cenários E2E, com cinco respostas autorizadas e dezessete recusas esperadas. Os positivos conferem versão, integridade, auditoria e finalização contratual. Os negativos conferem status, razão e ausência de conteúdo clínico.

Não se espera igualdade de identificadores, datas, versões numéricas do HAPI, endereços de contratos, hashes de respostas ou tempos. Esses valores dependem da execução e do histórico do laboratório. Uma versão histórica fixada pelo manifesto deve continuar sendo entregue mesmo quando houver versão corrente mais recente.

## Pré-requisitos

- Windows com PowerShell, Git e OpenSSL disponíveis no `PATH`.
- Node.js 24.10.0 e npm 11.6.1, versões do executor usadas na avaliação. O gateway usa o runtime declarado em `docker/middleware.Dockerfile`.
- Docker Desktop iniciado, em modo de contêineres Linux, com Docker Compose v2 e permissão de acesso ao daemon.
- Internet para instalar as dependências do lockfile e obter as imagens. A primeira inicialização também constrói imagens locais.
- Portas locais livres: 3001, 3002, 4001, 4002, 5433, 5435, 8081, 8082, 8180, 8190 e 8546. Sub-rede `/24` sem sobreposição com redes Docker existentes.

Não há mínimo de CPU/RAM validado por uma campanha de dimensionamento. O ambiente observado está documentado junto às evidências. Linux/macOS não foram certificados por este protocolo: a preparação automática de PKI invoca `powershell.exe`.

## Execução em clone novo

Clone `https://github.com/joao-valadares/InterFHIR-TCC.git` e abra o PowerShell na pasta `InterFHIR-TCC`, onde está `package.json`. Use uma pasta com acesso de escrita. Não copie `.env.example` para `.env` para este fluxo: o executor prepara as configurações locais.

Execute os comandos na ordem abaixo. A função interrompe a sequência se um comando falhar, inclusive no Windows PowerShell 5.1, em que `$ErrorActionPreference` sozinho não trata códigos de saída de programas nativos.

```powershell
$ErrorActionPreference = 'Stop'
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Falha em $Program (codigo $LASTEXITCODE). Interrompa e confira a saida."
    }
}

Invoke-Checked -Program git -Arguments @('status', '--short')
Invoke-Checked -Program docker -Arguments @('info', '--format', '{{.OSType}}')
Invoke-Checked -Program openssl -Arguments @('version')
Invoke-Checked -Program npm -Arguments @('ci')

# Troque apenas se esta sub-rede estiver ocupada. Use a mesma em toda a sessao.
$env:INTERFHIR_BESU_SUBNET = '172.31.241.0/24'
Invoke-Checked -Program npm -Arguments @('run', 'compile')
Invoke-Checked -Program npm -Arguments @('run', 'typecheck')
Invoke-Checked -Program npm -Arguments @('run', 'e2e:up')
Invoke-Checked -Program npm -Arguments @('run', 'e2e:wait')
Invoke-Checked -Program npm -Arguments @('test')
Invoke-Checked -Program npm -Arguments @('run', 'e2e:run')
Invoke-Checked -Program npm -Arguments @('run', 'docs:check')
```

`e2e:up` gera chaves/certificados locais, prepara os serviços, implanta e cadastra contratos, participantes e as políticas experimentais. O nome padrão do projeto Docker deriva do caminho do clone. O preflight recusa portas ocupadas, sub-rede conflitante ou recursos com identidade incompatível; não remova recursos de outros projetos para contornar essas verificações.

Suíte e E2E devem executar sequencialmente. Não inicie outra campanha sobre os mesmos bancos enquanto uma estiver ativa. `verify:all` é uma alternativa que separa os testes por categoria; para obter um único relatório `tests-all.json`, use o protocolo acima.

## Conferir os resultados

```powershell
$suite = Get-Content reports/tests-all-latest.json -Raw | ConvertFrom-Json
$suite.source
$suite.report | Select-Object status, category, stats, sourceBefore, sourceAfter

$e2e = Get-Content reports/e2e-latest.json -Raw | ConvertFrom-Json
$e2e.source
$e2e.report.summary
$e2e.report.scenarios |
    Select-Object id, status, outcome, httpStatus, reason, dataDelivery |
    Format-Table -AutoSize
```

Exija `status=passed`, nenhuma falha, pendência ou bloqueio e as contagens esperadas para a revisão executada. `npm test` verifica também que todas as categorias/arquivos foram representados e que os fontes não mudaram durante a suíte. Uma resposta HTTP 403 esperada pode corresponder a um **teste aprovado**.

Os arquivos `*-latest.json` são ponteiros substituíveis. Cada execução também grava uma cópia identificada em `reports/runs/`; cite essa cópia e seu `source`, não apenas o ponteiro. Relatórios de execuções interrompidas também são evidência e não devem ser apresentados como sucesso. A revisão atual preserva o mesmo envelope de proveniência no ponteiro E2E e na cópia histórica; ponteiros antigos podem conter apenas o relatório interno.

O campo `sourceHashScope=repository-execution-v2` identifica a inclusão de fixtures e configurações de infraestrutura no hash, além de código, testes, scripts, Docker e arquivos de dependências. Relatórios históricos sem esse campo usam o escopo anterior e mantêm seus hashes originais. As imagens externas estão fixadas por digest nos Compose/Dockerfiles, e `.gitattributes` mantém as terminações de linha dos fontes iguais entre clones.

## Repetição e encerramento

Para repetir com estado existente, mantenha a mesma configuração e execute novamente `e2e:up`, `e2e:wait` e os testes. A preparação renova os metadados assinados de curta duração. Se passou muito tempo entre preparação e ensaio, prepare novamente antes de interpretar expiração como defeito de autorização.

```powershell
npm run e2e:down
```

Esse comando para os contêineres do projeto e preserva contêineres, redes e volumes. Assim, outro clone deve usar uma sub-rede diferente enquanto a rede anterior existir. Para um ensaio **deliberadamente novo e descartável**, o comando abaixo remove os contêineres/redes Compose e apaga os volumes do projeto identificado. Chaves e demais arquivos de `.local` permanecem; um novo clone é o caminho para um laboratório totalmente novo. Não o use sobre uma campanha cujos dados precisam ser preservados:

```powershell
npm run e2e:reset -- --discard-data
```

O caso de adulteração histórica altera temporariamente uma versão sintética no PostgreSQL do HAPI, verifica a retenção e restaura o conteúdo. Não execute esse avaliador sobre um ambiente clínico real. O utilitário valida o projeto/recurso e conserva backup local para a restauração.

## Diagnóstico

| Sintoma | Verificação |
| --- | --- |
| Acesso negado ao daemon Docker | Verifique Docker Desktop, contêineres Linux e permissão da sessão. É bloqueio de ambiente, não aprovação do teste. |
| `HOST_PORT_UNAVAILABLE` | Libere a porta ocupada ou configure `INTERFHIR_*_HOST_PORT` conforme `scripts/runtime-environment.ts`; mantenha as mesmas variáveis na sessão. |
| `BESU_SUBNET_CONFLICT` | Escolha uma `/24` livre; não exclua redes alheias. |
| Falha de download/build | Verifique acesso aos registries e a saída do processo. Não avance após código de saída diferente de zero. |
| PKI/OpenSSL | Confirme `openssl version`; o gerador usa configuração própria e não depende do `openssl.cnf` do host. |
| `failed` ou `blocked` no relatório | Preserve o diretório da execução e examine a razão. Corrigir a causa e repetir não transforma o relatório anterior em aprovado. |

## Alcance

A aprovação demonstra o fluxo funcional sob o ambiente e a revisão registrados. Não garante disponibilidade de registries, recursos de qualquer computador, certificação FHIR/UDAP, segurança produtiva ou desempenho. O TCC preserva uma ocorrência histórica de HTTP 500 sem diagnóstico conclusivo; uma nova aprovação isolada não apaga esse antecedente.

O Dockerfile do gateway instala também ferramentas classificadas como desenvolvimento, pois usa Hardhat no início da aplicação. Por isso, `npm audit --omit=dev` sozinho não descreve toda a superfície da imagem; a auditoria completa e a avaliação de publicação devem considerar essas dependências.
