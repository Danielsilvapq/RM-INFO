# RM Informática — Controle de inventário

Sistema para inventariar os equipamentos dos clientes, controlar as visitas periódicas e as manutenções preventivas, e guardar as senhas de roteadores, Wi-Fi, DVRs e sistemas.

## O que o sistema faz

- **Clientes**: cadastro completo (CNPJ/CPF, contatos, WhatsApp, endereço, contrato, valor mensal) e de quantos em quantos dias você visita cada um.
- **Equipamentos**: cadastro detalhado por tipo, sempre com marca, modelo, número de série, patrimônio, setor, local, andar, usuário responsável, garantia e nota fiscal.
  - **Computadores, notebooks e servidores**: processador, placa-mãe, BIOS, memória (total, tipo, pentes, slots), HDs/SSDs (tipo, capacidade, modelo, série, saúde), placa de vídeo, fonte, sistema operacional (versão, licença, chave, ativação), hostname, domínio, Office, antivírus (com validade), backup, softwares, rede (IP, máscara, gateway, DNS, MAC), AnyDesk/TeamViewer e monitores.
  - **Impressoras**: tecnologia, função, cor, duplex, ADF, conexão, IP, MAC, fila, driver, painel web, toner/cilindro/fusor, contador de páginas, franquia e locação.
  - **Roteadores / rede**: função, IP, painel, firmware, DHCP, provedor, plano, PPPoE/IP fixo, VLANs e as redes Wi-Fi (SSID, banda, segurança).
  - **DVR / NVR**: canais, câmeras (canal, local, modelo, situação), HD, dias de gravação, portas, P2P/ID na nuvem, aplicativo e DDNS.
  - **Nobreaks** e **outros equipamentos**.
- **Atendimentos e manutenções**: visita periódica, preventiva, corretiva, instalação, remoto. Para cada atendimento: equipamentos atendidos, checklist, o que foi feito, peças trocadas, leitura do contador das impressoras, pendências para a próxima visita, valor cobrado e relatório para imprimir com espaço para assinatura.
- **Avisos**: o painel mostra as visitas e as preventivas atrasadas e as que vencem nos próximos dias (15 por padrão), os agendamentos, os atendimentos em aberto e as garantias e antivírus vencendo. Também pode avisar pelo navegador.
- **Senhas (cofre)**: senhas de Wi-Fi (SSID), roteadores, DVRs, sistemas, e-mails e servidores, ligadas ao cliente e ao equipamento. Ficam **criptografadas** no servidor (AES-256), só aparecem quando alguém clica em "mostrar" ou "copiar", e **cada visualização fica registrada** (quem, quando e de qual IP).
- **Etiquetas Zebra**: modelos de etiqueta 100% configuráveis. Você escolhe o tamanho (mm), o espaço entre etiquetas (gap), o sensor do rolo, se a etiqueta sai deitada, a resolução (203/300/600 dpi), o tipo de impressão (térmica direta ou com ribbon), a escuridão e a velocidade, e monta a etiqueta com texto, código de barras, QR code, logo, linhas e caixas, arrastando os elementos na pré-visualização. Cada elemento mostra um dado do equipamento (número de série, modelo, marca, patrimônio, setor, IP...), um texto fixo ou um **campo preenchido na hora de imprimir** (corredor, prateleira, posição, ponto de rede...). Os modelos ficam salvos para usar de novo. O modelo padrão é o de 80 × 20 mm com gap de 3 mm, e o botão "Calibrar" faz a Zebra medir o rolo. A logo da RM já vem nos modelos padrão; em Configurações dá para trocar pela logo oficial. Para imprimir, marque os equipamentos (ou digite uma etiqueta avulsa) e envie:
  - **Zebra na rede**: o servidor manda direto para o IP da impressora (porta 9100). O servidor precisa estar na mesma rede da Zebra.
  - **Zebra no USB**: pelo programa gratuito Zebra Browser Print instalado no computador.
  - **Arquivo .zpl** ou **código ZPL** para copiar.
- **Usuários**: administrador e técnico. O técnico só vê o cofre de senhas se o administrador liberar.
- **Planilha**: exporta o inventário (com todos os campos) para Excel.

## Demonstração

Abra o `index.html` direto no navegador (dois cliques) e o sistema entra no **modo demonstração**: dados fictícios de 4 clientes, 25 equipamentos, atendimentos e senhas, tudo salvo só naquele navegador. Na tela de entrada aparecem os acessos de exemplo:

- **Administrador**: usuário `admin`, senha `rm2026`
- **Técnico**: usuário `tecnico`, senha `1234` (não vê o cofre de senhas)

No menu lateral, "Restaurar dados de exemplo" volta tudo ao estado inicial. Na demonstração, a impressão e os downloads ficam desligados.

Quando o mesmo `index.html` é aberto pelo servidor (`servidor/`), ele entra no modo de verdade, com login real e dados no banco.

## Como a periodicidade é calculada

- **Preventiva do equipamento**: usa o prazo do próprio equipamento. Se ele não tiver, usa o do cliente e, por último, o padrão do tipo (em Configurações: computadores 180 dias, impressoras 90, etc.). A contagem começa na última preventiva registrada.
- **Visita ao cliente**: última "Visita periódica" ou "Manutenção preventiva" + a quantidade de dias do cliente. Se o atendimento tiver a "Próxima visita" preenchida, ou se houver um atendimento "Agendado", vale essa data.

## Como rodar

Precisa do [Node.js](https://nodejs.org) 22.13 ou mais novo. O sistema não tem outras dependências.

- **Windows**: clique duas vezes em `Iniciar sistema local.bat`.
- **Mac**: clique duas vezes em `Iniciar sistema local.command`.
- **Terminal**: `cd servidor && npm start`.

Abra http://localhost:3300 e entre com o usuário `admin` e a senha `rminfo`. **Troque a senha no primeiro acesso** (menu "Minha senha").

Outros computadores e celulares da mesma rede acessam pelo IP da máquina que roda o sistema (ex.: `http://192.168.0.10:3300`).

## Onde ficam os dados

- `servidor/dados/rminfo.db`: o banco de dados.
- `servidor/dados/backups/`: um backup automático por dia (guarda os últimos 30).
- `servidor/dados/chave-senhas.key`: a chave que abre as senhas guardadas. **Faça uma cópia dela num lugar seguro.** Sem ela, as senhas do cofre não podem ser recuperadas, nem a partir dos backups.

A pasta `dados/` não vai para o GitHub.

## Variáveis opcionais do servidor

| Variável | Para quê |
|---|---|
| `PORT` | porta (padrão 3300) |
| `ADMIN_SENHA_INICIAL` | senha do admin criado no primeiro uso |
| `CHAVE_SENHAS` | chave das senhas (64 caracteres hex) em vez do arquivo |
| `DB_FILE`, `BACKUP_DIR`, `BACKUP_DIAS` | onde ficam o banco e os backups |
| `TRUST_PROXY=1` | quando estiver atrás de um proxy HTTPS (Caddy/Nginx) |
