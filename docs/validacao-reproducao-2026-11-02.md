# Validação da reprodução — 2 de novembro de 2026

## Objeto e resultado

A revisão executável `f9f6a1a56644fc3280923e695c207a0ec52a85c5` foi validada em um clone local novo do repositório, sem reutilizar `node_modules`, PKI ou volumes de dados. O cache de imagens base do Docker foi reutilizado. Não foi um download de um repositório público: a publicação remota e o acesso da banca ainda não foram testados.

O protocolo de [reprodução](reproducao.md) concluiu instalação por lockfile, compilação, verificação de tipos, preparação do laboratório, prontidão, suíte completa, E2E e verificação documental. A suíte registrou **433 aprovações, zero falhas e zero pendências**. O primeiro E2E registrou **22 aprovações, zero falhas e zero bloqueios**, com cinco entregas autorizadas e dezessete recusas esperadas. A [matriz TCC–código](correspondencia-tcc-codigo.md) delimita o que cada controle efetivamente demonstra.

A distribuição pública foi preparada a partir da revisão local `724b7cdb3e8f858df8d30dc755f832d6ab67e0a0`, com um único commit inicial e sem importar o histórico anterior. As referências a revisões nos JSON identificam os ensaios originais; a equivalência do código da distribuição é estabelecida pelo hash de execução abaixo. A publicação não reescreve os relatórios nem representa uma nova execução dos testes.

## Evidências e identidade dos fontes

| Execução | Estado inicial | Resultado | Registro imutável |
| --- | --- | --- | --- |
| Suíte completa, 01/11/2026 | Clone novo; laboratório preparado pelo protocolo | 433 aprovados, 0 falhas, 0 pendências | [tests-all.json](../reports/runs/2026-11-01T18-08-37-180Z-bcf4bdcb/tests-all.json) |
| E2E, 01/11/2026 | Mesmo laboratório, após a suíte | 22 aprovados, 0 falhas, 0 bloqueios | [e2e.json](../reports/runs/2026-11-01T18-13-09-984Z-df11a1da/e2e.json) |
| E2E, 02/11/2026 | Volumes existentes; metadados renovados pelo protocolo | 22 aprovados, 0 falhas, 0 bloqueios | [e2e.json](../reports/runs/2026-11-02T17-36-32-825Z-085c3650/e2e.json) |

Os registros têm `sourceHashScope=repository-execution-v2` e hash SHA-256 dos fontes de execução:

```text
174afe7b10fd6f2b92348bce6a71c1e238081740c0bf4a2bf389821f37675a67
```

A suíte preservou o mesmo hash antes e depois dos testes, e o E2E identificou os mesmos fontes. O campo `dirty=true` nos registros E2E inclui a geração de relatórios pelo próprio protocolo; não indica, isoladamente, mudança de código. Os ponteiros atuais foram comparados byte a byte com suas cópias por execução. Documentação e relatórios acrescentados depois dos ensaios não fazem parte do escopo desse hash; a revisão Git registrada nos JSON é a revisão efetivamente executada, e não é reescrita para o commit que reúne a documentação final.

## Ambiente e procedimento

O [registro do ambiente](../reports/validation-2026-11-02/environment.json) identifica Windows 11, Node.js 24.10.0, npm 11.6.1, Git 2.51.0, OpenSSL 3.6.1, Docker 28.5.1 e Compose 2.40.0. O host tinha aproximadamente 16 GiB de memória e o Docker aproximadamente 8 GiB, em Linux x86_64. Os fontes do clone usavam LF. As seis imagens externas dos Compose/Dockerfiles estão fixadas por digest; o lockfile de dependências foi preservado.

Foram executados, sequencialmente, `npm ci`, `npm run compile`, `npm run typecheck`, `npm run e2e:up`, `npm run e2e:wait`, `npm test`, `npm run e2e:run` e `npm run docs:check`, com interrupção em código de saída diferente de zero. A repetição com os volumes existentes refez `e2e:up` e `e2e:wait` antes do E2E, renovando os metadados assinados de curta duração.

A primeira tentativa de preparação do clone de validação detectou `BESU_SUBNET_CONFLICT`: a rede `172.31.241.0/24` ainda pertencia a outro laboratório parado. A execução prosseguiu com a sub-rede livre `172.31.242.0/24`, sem remover redes alheias. Esse bloqueio de pré-requisito não foi contado como teste aprovado. `e2e:down` apenas para os contêineres e conserva redes e volumes; um novo clone precisa de sub-rede livre.

## Correspondência e limites

As correções desta revisão afetam documentação, preparação e proveniência das evidências. Não alteram os contratos Solidity nem a lógica em `middleware/src`. Os três novos testes de regressão cobrem fixação das imagens, inclusão de `fixtures`/`infra` na identidade dos fontes e preservação do envelope do relatório E2E. Os 430 testes e 22 cenários de outubro citados na monografia permanecem resultados históricos da campanha original.

As execuções verificam equivalência funcional das asserções: leitura autorizada com versão e integridade verificadas, auditoria correlacionada e retenção nos casos negativos. Identificadores, datas, números de versão FHIR, hashes de recursos e durações podem mudar entre laboratórios. Não se exige igualdade literal desses valores.

A auditoria de dependências registrou **34 alertas: 9 baixos, 6 moderados e 19 altos, sem críticos**; consulte o [resumo da auditoria](../reports/validation-2026-11-02/dependency-audit.json). Embora a consulta com `--omit=dev` tenha retornado zero alertas, o gateway instala e utiliza ferramentas de desenvolvimento, incluindo Hardhat, durante sua execução. Portanto, esse resultado parcial não significa que a imagem esteja livre das dependências sinalizadas. Não foi aplicada atualização forçada do lockfile, nem foi realizada auditoria de vulnerabilidades de todas as imagens Docker.

O resultado sustenta a reprodução do laboratório acadêmico no ambiente descrito. Não garante execução em qualquer máquina, disponibilidade futura dos registries, implantação produtiva ou ausência de vulnerabilidades. A ocorrência histórica de HTTP 500 registrada no TCC continua sem causa conclusiva; o sucesso destes ensaios não resolve retroativamente aquela ocorrência. Governança independente, certificação FHIR/UDAP e desempenho permanecem fora do que foi demonstrado.
