# LPA2v-AppSec

Simulador de um **cluster hierárquico de neurônios paraconsistentes LPA2v**
aplicado à triagem de findings de segurança de aplicação (SAST/SCA/DAST),
com foco em **redução de falsos positivos** e **correlação contextual**.

Este projeto é uma adaptação de domínio de um trabalho acadêmico original
sobre monitoramento de redes industriais — *"Cluster Hierárquico de
Neurônios Paraconsistentes LPA2v para uma Engine Inteligente de
Monitoramento de Redes Industriais visando a Redução de Falsos Positivos e
a Correlação Contextual de Eventos"* (Alexandre de Carvalho, Mestrado em
Engenharia Mecânica, Universidade Santa Cecília). O artigo original valida
a arquitetura em telemetria de CLPs, switches industriais, SCADA e OPC UA.
Aqui, o mesmo núcleo teórico (lógica paraconsistente anotada de dois
valores — LPA2v) é reaplicado a um domínio completamente diferente:
**triagem de achados de scanners de segurança de aplicação** (Semgrep,
Snyk, OWASP ZAP), correlacionando-os com contexto de código e contexto
operacional para decidir o que realmente merece virar alerta.

> **Este é um simulador com dados sintéticos**, não uma ferramenta rodando
> contra scanners reais. O objetivo é demonstrar e permitir que terceiros
> reproduzam/validem a arquitetura e sua lógica de decisão — não medir
> desempenho de produção. Ver [Limitações](#limitações).

## Por que lógica paraconsistente aqui

Ferramentas de AppSec frequentemente discordam entre si, e essa discordância
é informação, não ruído a ser descartado. Um scanner SAST pode acusar um
endpoint sem autenticação enquanto um scanner DAST tenta explorá-lo em
runtime e é bloqueado por um WAF — a lógica clássica força uma decisão
binária ("é vulnerável" ou "não é") e descarta um dos dois sinais. A LPA2v
não força essa escolha: ela representa evidência **favorável** (`μ`) e
**desfavorável** (`λ`) separadamente e permite que ambas coexistam.

Para uma proposição P ("este achado é uma vulnerabilidade real"):

```
GC  = μ - λ        grau de certeza      (∈ [-1, 1])
GCT = μ + λ - 1     grau de contradição  (∈ [-1, 1])
```

`GC` alto e positivo → evidência aponta fortemente para "é real".
`GC` baixo/negativo → aponta para "não é real" (ou não há evidência).
`GCT` alto → `μ` e `λ` são **ambos** altos ao mesmo tempo: contradição
genuína, não um empate a ser resolvido — deve virar um estado
**inconsistente**, sinalizado para revisão humana, em vez de um veredito
forçado.

## Arquitetura

```
sinal bruto (SAST, SCA, DAST, contexto de código, contexto operacional)
        │
        ▼
neurônios de domínio (um por fonte) ── cada um estima (μ, λ)
        │
        ▼
neurônio mestre ── DUAS agregações, não uma:
   • consenso  = média ponderada de μ e de λ entre os domínios
                  → decide o ranking normal/atenção/degradação/crítico
   • contradição = maior μ entre os DETECTORES PRIMÁRIOS (SAST/SCA/DAST)
                    vs. maior λ entre eles (podem vir de detectores
                    diferentes) → decide se o estado é "inconsistente"
        │
        ▼
persistência temporal (janela de N scans) ── evita que um pico isolado
        │                                       ou um scanner instável
        ▼                                       dispare alerta direto
classe final: normal | atenção | degradação | crítico | inconsistente
```

**Por que duas agregações e não uma?** Testado durante a calibração deste
projeto: se você agrega μ e λ por média ponderada simples entre *todos* os
domínios, uma contradição real entre dois detectores específicos (ex.:
SAST grita "sim", DAST grita "não") é **diluída pela média** dos outros
domínios neutros e nunca dispara `GCT` alto — exatamente o oposto do que a
lógica paraconsistente deveria fazer. Por isso a detecção de contradição
usa os extremos entre detectores primários, e a média ponderada fica
reservada para decidir o *ranking* de severidade quando não há conflito.
Contexto de código/operacional fica de fora do cálculo de contradição de
propósito: eles são metadado explicativo (por que o achado apareceu), não
"mais um voto sobre existir vulnerabilidade" — quando o contexto explica um
achado (ex.: janela de manutenção autorizada), o resultado correto é
suprimir a severidade, não abrir um caso de revisão humana.

## Mapeamento: redes industriais → AppSec

| Artigo original (redes industriais) | Este projeto (AppSec) |
|---|---|
| Disponibilidade, performance, rede, aplicação, contexto operacional | SAST (Semgrep), SCA (Snyk), DAST (ZAP), contexto de código, contexto operacional |
| 200 ativos monitorados | ~200 ativos sintéticos distribuídos entre 12 cenários |
| Persistência de 5 min antes de classificar | Persistência de N scans consecutivos antes de escalar |
| Estado "inconsistente" (ICMP indisponível + SNMP/OPC UA ativos) | Endpoint com WAF: SAST acusa, DAST tenta explorar e é bloqueado |
| Backup autorizado explica CPU/memória altas | Janela de pentest autorizado explica achados DAST reais |
| Loop Ethernet progressivo (antecipação) | Vazamento de segredo redescoberto progressivamente |
| GC = μ - λ, GCT = μ + λ - 1 | Idêntico — núcleo teórico não muda entre domínios |

## Os 12 cenários simulados

Cada cenário gera eventos sintéticos (ativo × tick de scan) com uma verdade
fundamental (`groundTruthVulnerable`) conhecida pelo simulador mas invisível
aos três mecanismos avaliados:

1. **dep-bump** — migração de dependência gera ruído SCA sem exploração real.
2. **waf-shield** — SAST acusa falta de auth; DAST tenta explorar e é bloqueado. Contraditório de propósito.
3. **secret-sprawl** — vazamento de segredo com evidência fraca no início, escalando ao longo do tempo.
4. **pentest-window** — achados DAST reais durante teste de invasão autorizado.
5. **staging-noise** — achados SAST recorrentes em ambiente de baixo tráfego.
6. **flaky-scanner** — achado SAST intermitente por instabilidade do próprio scanner.
7. **confirmed-rce** — SAST + SCA + DAST concordam: RCE crítico real, público, sem auth.
8. **confirmed-sqli** — SAST + DAST concordam: SQLi real e explorável.
9. **deprecated-module** — achados persistentes em módulo depreciado, não público, inatingível.
10. **test-fixture** — achados em credenciais/payloads de exemplo usados só em testes.
11. **silent-supply-chain** — dependência com exploit ativo, carregada dinamicamente; só o SCA enxerga.
12. **internal-ambiguity** — achados moderados em serviço apenas acessível via rede interna.

## Como rodar

```bash
pnpm install
pnpm sim        # roda a simulação e imprime o comparativo no terminal
pnpm test       # testes unitários do núcleo paraconsistente
pnpm typecheck
```

`npm`/`yarn` também funcionam (`npm install && npm run sim`) — o projeto não
depende de nenhum recurso exclusivo do pnpm, e os resultados são idênticos
entre gerenciadores (mesma seed, mesmo output).

`pnpm sim` aceita uma seed opcional (`pnpm sim -- 123`) — a mesma seed
sempre produz a mesma simulação, para que terceiros consigam reproduzir
exatamente os mesmos números. Os resultados completos (por evento) são
exportados para `out/results.json` e `out/events.csv`.

## Gráficos (para o artigo)

As figuras são geradas por um script Python separado em `plots/`, que só lê
os arquivos já exportados por `pnpm sim` — não reimplementa nenhuma lógica
de classificação. Precisa rodar a simulação pelo menos uma vez antes.

```bash
python3 -m venv plots/.venv
plots/.venv/bin/pip install -r plots/requirements.txt
plots/.venv/bin/python plots/make_figures.py
```

Gera, em `plots/figures/` (PDF + SVG + PNG a 300dpi, para LaTeX ou Word):

- `fig1_diagrama_conceitual` — evolução threshold → rule-based → cluster hierárquico LPA2v
- `fig2_metricas_principais` — precisão/recall/F1 por mecanismo
- `fig3_volume_erros` — verdadeiros positivos, falsos positivos, falsos negativos
- `fig4_evolucao_secret_sprawl` — classificação ao longo do tempo no cenário progressivo
- `fig5_heatmap_waf-shield` e `fig6_heatmap_flaky-scanner` — os 3 mecanismos lado a lado (mesma escala de cor), mostrando estado inconsistente vs. ruído espalhado
- `fig7_alertas_acumulados` — alertas acumulados ao longo da simulação

Os nomes dos arquivos batem 1 para 1 com o número da "Figura N" usado no texto do artigo.

Paleta e especificações de marca (ordem categórica fixa, uma única escala
por eixo, grades sólidas, rótulos diretos seletivos) seguem uma metodologia
de data-viz validada para segurança daltônica — cores testadas com
`node scripts/validate_palette.js` antes de entrarem no script.

## Resultados (seed padrão = 42)

```
Cenarios: 12 | Ativos: 206 | Eventos totais: 3005

| Mecanismo     | Precisao | Recall | F1     | TP  | FP   | FN  | Alertas | Inconsist. | Total |
| ------------- | -------- | ------ | ------ | --- | ---- | --- | ------- | ---------- | ----- |
| threshold     | 8.01%    | 86.80% | 14.66% | 217 | 2493 | 33  | 2710    | 0          | 2710  |
| rule-based    | 10.41%   | 86.80% | 18.59% | 217 | 1868 | 33  | 2085    | 0          | 2085  |
| lpa2v-cluster | 100.00%  | 65.60% | 79.23% | 164 | 0    | 86  | 164     | 300        | 464   |
```

*(os números exatos podem variar levemente por seed/versão — rode `npm run
sim` para os valores atuais; os acima são de uma execução de referência.)*

Leitura honesta desses números:

- **Falsos positivos: 2493 (threshold) → 1868 (rule-based) → 0
  (LPA2v-cluster).** Este é o resultado central, e reproduz qualitativamente
  o achado do artigo original: a correlação contextual elimina o excesso de
  alarme, não apenas suprime alertas aleatoriamente.
- **Recall caiu de 86,8% para 65,6%.** Isso é esperado e intencional: três
  dos doze cenários (`secret-sprawl`, `silent-supply-chain` e o aquecimento
  da persistência temporal em `confirmed-rce`/`confirmed-sqli`) foram
  desenhados especificamente para serem difíceis — evidência fraca, de um
  único domínio, ou nos primeiros ticks antes da janela de persistência se
  preencher. O cluster ainda captura a maioria desses casos (inclusive o
  cenário de supply-chain silencioso, que nenhum mecanismo baseado em regras
  fixas veria de forma seletiva), mas com atraso ou parcialmente.
- **300 eventos do cenário `waf-shield` foram corretamente roteados para
  "inconsistente"**, nem normal nem crítico — exatamente o comportamento que
  threshold e rule-based são estruturalmente incapazes de expressar.
- **A antecipação de detecção (cenário `secret-sprawl`) não replicou o
  ganho do artigo original nesta calibração**: o cluster ficou ~4 ticks
  *atrás* do threshold bruto nesse cenário específico, porque exige
  corroboração entre detectores + persistência sustentada antes de escalar
  além de "atenção" — uma troca deliberada de velocidade por confiabilidade
  quando só um domínio (SAST) carrega a maior parte da evidência. Reportar
  isso como está, em vez de recalibrar até "funcionar", é intencional: o
  objetivo deste repositório é permitir validação por terceiros, não vender
  um resultado.

## Limitações

Mesma ressalva do artigo original, adaptada:

- **Dados sintéticos, não achados reais.** Os cenários foram desenhados para
  ilustrar categorias de comportamento (contradição, contexto explicativo,
  evidência progressiva, recall difícil), não para replicar a distribuição
  estatística de findings reais do Semgrep/Snyk/ZAP.
- **Pesos e limiares foram calibrados manualmente** durante o
  desenvolvimento deste simulador (ver `DEFAULT_WEIGHTS` em
  `src/cluster/masterNeuron.ts` e `DEFAULT_THRESHOLDS` em
  `src/core/paraconsistent.ts`), não aprendidos a partir de dados
  rotulados. Calibração adaptativa a partir de findings reais e rotulados
  (confirmados vs. descartados) é o próximo passo natural, assim como o
  artigo original aponta para trabalhos futuros com telemetria real.
- **Persistência temporal usa "ticks" (ciclos de scan), não minutos.** O
  valor por padrão (3 ticks) é um parâmetro, não uma constante teórica.
- Resultados devem ser lidos como validação de arquitetura em ambiente
  simulado — não como benchmark de desempenho operacional de um pipeline
  de AppSec real.

## Estrutura do código

```
src/core/           tipos de domínio + núcleo LPA2v (μ, λ, GC, GCT, classificação)
src/neurons/        um neurônio por fonte de evidência (SAST, SCA, DAST, contexto de código, contexto operacional)
src/cluster/        neurônio mestre (consenso + contradição) e persistência temporal
src/mechanisms/      os três mecanismos comparados: threshold, rule-based, lpa2v-cluster
src/simulator/       gerador de ativos e dos 12 cenários sintéticos
src/metrics/         matriz de confusão, precisão/recall/F1, antecipação de detecção
src/report/           impressão de tabela no terminal + export JSON/CSV
scripts/run-simulation.ts   ponto de entrada (`npm run sim`)
tests/               testes unitários do núcleo paraconsistente
```

## Referências

- N. C. A. da Costa, "On the theory of inconsistent formal systems," *Notre
  Dame Journal of Formal Logic*, vol. 15, no. 4, pp. 497–510, 1974.
- J. M. Abe (Ed.), *Paraconsistent Intelligent-Based Systems: New Trends in
  the Applications of Paraconsistency*, Springer, 2015.
- Alexandre de Carvalho, *Cluster Hierárquico de Neurônios Paraconsistentes
  LPA2v para uma Engine Inteligente de Monitoramento de Redes Industriais
  visando a Redução de Falsos Positivos e a Correlação Contextual de
  Eventos*, Mestrado em Engenharia Mecânica, Universidade Santa Cecília
  (artigo original que este projeto adapta para o domínio de AppSec).

## Licença

MIT.
