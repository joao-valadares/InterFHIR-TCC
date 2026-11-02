# Avaliação ampliada — 15 de outubro de 2026

Esta campanha amplia a avaliação funcional usada na monografia. Contratos, `middleware/src` e scripts principais de execução foram preservados. As alterações executáveis restringem-se aos testes e a `scripts/e2e`, incluindo preparo das configurações experimentais pelas interfaces existentes.

## Resultados verificáveis

| Instrumento | Relatório imutável | Resultado |
| --- | --- | --- |
| Suíte completa | [tests-all.json](../reports/runs/2026-10-15T18-37-54-389Z-ee7e6ad4/tests-all.json) | 430/430; 56 arquivos; nenhuma falha ou pendência |
| E2E real | [e2e.json](../reports/runs/2026-10-15T18-37-20-276Z-1d987cf6/e2e.json) | 22/22; cinco positivos e dezessete negativos |
| Tentativa anterior | [e2e.json](../reports/runs/2026-10-15T18-23-21-602Z-e974d056/e2e.json) | 20 aprovados, dois bloqueados após erro de criação de Consent |

As duas execuções aprovadas compartilham `sourceHash=9e46dcbd4b478fb3935595cb36d41d427f8a72e6ef795c2559877e330a936d77`, revisão-base `8362df5bbc145e15fc66e205777337ccedb815d0`, `dirty=true`, Node.js v24.10.0 e Windows. A tipagem e `docs:check` passaram. Os dados atuais de host/Docker estão em [ambiente](../reports/environments/2026-10-15.json); volumes reutilizados, sub-rede `172.31.240.0/24`.

## Políticas e profissionais sintéticos

Os códigos representam categorias do ensaio, sem equivalência presumida com nomenclaturas clínicas oficiais. Todas as demais condições obrigatórias continuam exigidas.

| Política | Requisito | Consent | Recurso |
| --- | --- | --- | --- |
| Original | Papel 1, especialidade 1 | Restrito a Bruno | `Observation/obs-ana-1` |
| P1: `POLICY_E2E_GENERAL_OBSERVATION`, v1 | Papel 1, especialidade livre | Organização Clínica B | `Observation/obs-ana-1` |
| P2: `POLICY_E2E_SPECIALIST_OBSERVATION`, v1 | Papel 2, especialidade 2 | Organização Clínica B | `Observation/obs-ana-specialist` |

P1 autoriza Bruno (1/1) e Daniel (1/3) no mesmo compartilhamento; recusa Carla (2/2). P2 autoriza Carla (2/2); recusa Bruno por papel e especialidade incompatíveis e Diana (2/3) pela especialidade. Cada leitura percorre novamente decisão, `vread`, integridade, auditoria, finalização e revalidação. O handoff é de resgate único; o compartilhamento permite leituras sucessivas enquanto válido.

Os dados e políticas adicionais estão em [policy-variation-fixtures.ts](../scripts/e2e/policy-variation-fixtures.ts). O preparo [prepare-policy-variations.ts](../scripts/e2e/prepare-policy-variations.ts) usa administração já implementada. A [sobreposição Compose](../scripts/e2e/policy-variation.compose.yml) carrega as definições nos gateways pelo [ponto de entrada exclusivo do teste](../scripts/e2e/start-policy-variation-gateway.ts).

## Versão histórica e integridade real

O ensaio cria versões sucessivas da segunda Observation. Na campanha aprovada, o manifesto fixou versão 11, valor 82; o HAPI possuía versão corrente 12, valor 84. A resposta de Carla conservou versão 11 e hash esperado. Os números são coletados em cada execução e variam com o histórico do laboratório.

O cenário `tampered-historical-fhir-content` altera temporariamente apenas o valor histórico para 999 no PostgreSQL clínico, mantendo manifesto e identificadores. Uma consulta de avaliação confirma que o HAPI devolve o conteúdo alterado. O pedido institucional retorna 403 `MANIFEST_RESOURCE_HASH_MISMATCH`, com uma leitura interna, uma verificação de compromisso, um AuditEvent e finalização de retenção. O executor restaura os bytes originais e confere a restauração; `authorized-restored-historical-version` obtém novamente 200.

O [utilitário de mutação](../scripts/e2e/historical-fhir-mutation.ts) verifica a identidade do contêiner/projeto, restringe a injeção ao recurso sintético fixo e à versão não corrente, mantém backup em `.local/e2e/historical-backups` e usa substituição condicional. O `finally` restaura o conteúdo mesmo diante de falha da operação. O teste rejeita formato interno não suportado ou divergência concorrente; não sobrescreve uma mudança imprevista.

Esse teste é distinto de `tampered-fhir-version`, que modifica o vínculo no manifesto e alcança a barreira anterior ao `vread`.

## Concorrência e identidade: evidência isolada

Três testes em `health-access-service.test.ts` suspendem o `vread` após a decisão e alteram o Consent em tarefa concorrente: estado inativo, versão avançada ou referência autorizada diferente. A revalidação retém o recurso em todos, com uma leitura e nenhuma entrega. São testes de serviço com sincronização controlada; o E2E de revogação continua sendo posterior à operação coordenada.

Um teste de `udap-token-service.test.ts` confirma que a mesma chave institucional pode declarar dois identificadores profissionais distintos. Isso caracteriza a confiança na instituição, sem demonstrar login da pessoa que opera o software. A monografia concentra essa hipótese e suas consequências no modelo STRIDE.

## Ocorrência operacional preservada

A tentativa anterior parou no preparo do Consent de expiração: HTTP 500 `INTERNAL_ERROR`, operação `failed_recoverable` em `pending_chain`. O FHIR já havia sido criado, sem hash de transação registrado. Os vinte cenários anteriores, incluindo adulteração histórica e restauração, estavam aprovados. Expiração e revogação ficaram bloqueadas.

A repetição integral passou sem mudança do código principal. A causa não foi determinada; esse resultado não é uma correção da ocorrência nem prova de recuperação prolongada. Diagnóstico e eventual correção da lógica principal ficaram pendentes por escopo explícito do autor. O relatório incompleto foi preservado junto ao aprovado.

## Reprodução

Para executar a revisão atual deste repositório, use o [protocolo autossuficiente de reprodução](reproducao.md). Para conferir exatamente os fontes históricos de 15 de outubro, a entrega da monografia inclui separadamente o pacote `EscritaTCC/reproducibilidade/interfhir-fontes-2026-10-15.zip`; ele não faz parte deste repositório nem é necessário para reproduzir o comportamento atual. `npm run e2e:up` prepara as políticas e os profissionais adicionais. Depois de prontidão: `npm run typecheck`, `npm test`, `npm run e2e:run` e `npm run docs:check`. Execute suíte e E2E sequencialmente, pois compartilham o laboratório. A mutação histórica usa somente dados sintéticos e requer acesso ao Docker do projeto.

O laboratório permanece local, com uma administração, duas instituições sintéticas e quatro validadores. A evidência é funcional; tolerância bizantina experimental, identidade humana independente, autorização por campo e comportamento sob carga exigem outros ensaios.
