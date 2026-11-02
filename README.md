# InterFHIR

Prova de conceito acadêmica de controle de acesso interinstitucional a recursos HL7 FHIR. Combina Consent, identidade OIDC do paciente, autenticação institucional por mTLS/UDAP, políticas ABAC em contratos Solidity/Besu, manifesto assinado, leitura histórica e auditoria antes da resposta.

O fluxo estudado é **Hospital A → Clínica B**, com dados sintéticos e finalidade TREAT. O conteúdo clínico fica no HAPI custodiante, fora da blockchain. A resposta é entregue ao cliente institucional; não há cópia automática para o HAPI destinatário.

Repositório público da versão final: [https://github.com/joao-valadares/InterFHIR-TCC](https://github.com/joao-valadares/InterFHIR-TCC). Esta distribuição reúne a implementação em um único commit inicial. Os identificadores Git dos relatórios anteriores foram preservados como proveniência histórica e não são commits deste novo histórico; a correspondência dos fontes é conferida pelo `sourceHash` e pelo respectivo `sourceHashScope`.

## Para a banca

1. [Reprodução a partir de clone novo](docs/reproducao.md): pré-requisitos, comandos, resultado esperado e diagnóstico.
2. [Correspondência entre TCC e código](docs/correspondencia-tcc-codigo.md): afirmações, implementação, testes e limites.
3. [Guia técnico](docs/tcc-project-guide.md): arquitetura, contratos, identidade, autorização e liberação.
4. [Dois fluxos detalhados](docs/manual-e2e.md): mensagens ilustrativas de sucesso e negativa, separadas das observações históricas.
5. [OpenAPI](docs/openapi.yaml): rotas, esquemas e respostas.

A [validação de publicação](docs/validacao-reproducao-2026-11-02.md) registra 433 testes aprovados e duas execuções E2E de 22 cenários, em clone novo e com estado persistente, além do ambiente e das limitações.

## Executar

Use Windows/PowerShell, Git, OpenSSL, Node.js 24.10.0/npm 11.6.1 e Docker Desktop com contêineres Linux. Na raiz de um clone novo, execute cada comando somente se o anterior terminar com código zero:

```powershell
npm ci
$env:INTERFHIR_BESU_SUBNET = '172.31.241.0/24'
npm run compile
npm run typecheck
npm run e2e:up
npm run e2e:wait
npm test
npm run e2e:run
npm run docs:check
```

A sub-rede e as portas precisam estar livres. O [protocolo completo](docs/reproducao.md) inclui interrupção automática em falhas. A preparação gera chaves, certificados, configurações e dados sintéticos; não copie arquivos ignorados da máquina do autor. Suíte e E2E executam sequencialmente.

O resultado esperado do E2E é **22 cenários aprovados: cinco leituras autorizadas e dezessete recusas esperadas**. Identificadores, datas, versões numéricas, hashes e durações variam. Compare as asserções e a proveniência, não os bytes dos relatórios.

`npm run e2e:down` para os contêineres do laboratório, preservando contêineres, redes e volumes. O reset com descarte é opcional e está explicado no protocolo. Não execute o avaliador sobre dados clínicos reais.

## Evidências usadas na monografia

A [campanha de 15/10/2026](docs/avaliacao-ampliada-2026-10-15.md) registrou:

- [430 testes aprovados, sem falhas ou pendências](reports/runs/2026-10-15T18-37-54-389Z-ee7e6ad4/tests-all.json).
- [22 cenários E2E aprovados](reports/runs/2026-10-15T18-37-20-276Z-1d987cf6/e2e.json), incluindo variação de políticas/profissionais, versão histórica e adulteração real seguida de restauração no HAPI.
- [Tentativa anterior incompleta](reports/runs/2026-10-15T18-23-21-602Z-e974d056/e2e.json), preservada com vinte aprovações e dois bloqueios.

Esses relatórios são históricos e identificam seus próprios fontes. Novas execuções geram diretórios em `reports/runs/` e atualizam ponteiros `*-latest.json`. A [matriz TCC–código](docs/correspondencia-tcc-codigo.md) registra separadamente a verificação atual do repositório.

## Organização

| Diretório | Conteúdo |
| --- | --- |
| `contracts` | Seis contratos Solidity de cadastro, políticas, autorização e auditoria |
| `middleware/src` | API, identidade, Consent, compartilhamento, manifesto, FHIR e liberação |
| `middleware/test`, `test` | Testes de unidade, contratos e integração |
| `scripts` | Preparação, ciclo de vida, execução dos testes e coleta de evidências |
| `docker`, `infra`, `fixtures` | Imagens, configurações e dados sintéticos |
| `docs` | Documentação técnica e protocolo da banca |
| `reports/runs` | Relatórios sanitizados por execução, incluindo falhas e bloqueios |
| `.local` | Material de execução gerado e ignorado pelo Git; não publicar |

## Limites

Laboratório local, com uma administração, duas instituições sintéticas e quatro validadores. O software institucional declara o profissional; não há autenticação humana independente pelo custodiante. A autorização é por recurso completo, e as revalidações não formam uma transação distribuída. Auditoria e finalização não comprovam recebimento humano.

A aprovação funcional não é certificação FHIR/UDAP, conformidade regulatória, ensaio de desempenho ou validação de produção. O gateway usa ferramentas de desenvolvimento em execução; avalie a auditoria completa de dependências antes de qualquer implantação fora do laboratório.
