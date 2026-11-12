// RM Informática — servidor sem dependências externas (Node 22.13+ com node:sqlite)
// Guarda clientes, equipamentos e atendimentos num banco SQLite e serve o sistema (index.html).
// Os dados ficam como "registros" (um por cliente, equipamento, atendimento...) para que duas pessoas
// usando ao mesmo tempo não apaguem o trabalho uma da outra.
// As senhas de roteadores, DVRs, Wi-Fi etc. ficam numa tabela separada, criptografadas (AES-256-GCM),
// e só são mostradas a quem tem permissão — cada visualização fica registrada.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3300;
const HOST = process.env.HOST || undefined;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const RAIZ = process.env.RAIZ || path.join(__dirname, '..');           // pasta com index.html e assets/
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'dados', 'rminfo.db');
const DADOS_DIR = path.dirname(DB_FILE);
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(DADOS_DIR, 'backups');
const BACKUP_DIAS = Number(process.env.BACKUP_DIAS) || 30;
const CHAVE_FILE = process.env.CHAVE_FILE || path.join(DADOS_DIR, 'chave-senhas.key');
const SESSAO_DIAS = 30;

fs.mkdirSync(DADOS_DIR, { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
db.exec(`
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY,
  nome TEXT NOT NULL,
  login TEXT NOT NULL UNIQUE COLLATE NOCASE,
  senha_hash TEXT NOT NULL,
  perfil TEXT NOT NULL DEFAULT 'tecnico',
  pode_senhas INTEGER NOT NULL DEFAULT 0,
  ativo INTEGER NOT NULL DEFAULT 1,
  criado_em TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS sessoes (
  token TEXT PRIMARY KEY,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  criado_em TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS registros (
  colecao TEXT NOT NULL,
  id TEXT NOT NULL,
  dados TEXT NOT NULL,
  versao INTEGER NOT NULL,
  apagado INTEGER NOT NULL DEFAULT 0,
  usuario_id INTEGER,
  atualizado_em TEXT DEFAULT (datetime('now','localtime')),
  PRIMARY KEY (colecao, id)
);
CREATE INDEX IF NOT EXISTS idx_registros_versao ON registros(versao);
CREATE TABLE IF NOT EXISTS credenciais (
  id INTEGER PRIMARY KEY,
  cliente_id TEXT,
  equipamento_id TEXT,
  tipo TEXT NOT NULL DEFAULT 'acesso',
  titulo TEXT NOT NULL,
  usuario TEXT,
  endereco TEXT,
  ssid TEXT,
  obs TEXT,
  senha_enc TEXT,
  criado_em TEXT DEFAULT (datetime('now','localtime')),
  atualizado_em TEXT DEFAULT (datetime('now','localtime')),
  atualizado_por INTEGER
);
CREATE TABLE IF NOT EXISTS log_senhas (
  id INTEGER PRIMARY KEY,
  credencial_id INTEGER,
  titulo TEXT,
  usuario_id INTEGER,
  usuario_nome TEXT,
  acao TEXT NOT NULL,
  ip TEXT,
  quando TEXT DEFAULT (datetime('now','localtime'))
);
`);

// ---------- utilidades ----------
class Erro extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const p2 = (n) => String(n).padStart(2, '0');
const fmtData = (d) => `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}`;

function hashSenha(senha) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(senha, salt, 64).toString('hex');
}
function confereSenha(senha, guardado) {
  const [salt, hash] = String(guardado).split(':');
  if (!salt || !hash) return false;
  const a = Buffer.from(hash, 'hex');
  const b = crypto.scryptSync(String(senha), salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function transacao(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
}
function validaSenha(s) {
  if (typeof s !== 'string' || s.length < 6) throw new Erro(400, 'A senha precisa ter pelo menos 6 caracteres');
  return s;
}
const texto = (v, max = 500) => (v === undefined || v === null ? '' : String(v).trim().slice(0, max));

// ---------- chave das senhas guardadas ----------
// Vem da variável CHAVE_SENHAS (64 caracteres hex) ou do arquivo dados/chave-senhas.key, criado no primeiro uso.
// SEM ESSA CHAVE AS SENHAS GUARDADAS NÃO PODEM SER LIDAS: guarde uma cópia dela fora do servidor.
function carregarChave() {
  const env = process.env.CHAVE_SENHAS;
  if (env) {
    if (!/^[0-9a-fA-F]{64}$/.test(env)) throw new Error('CHAVE_SENHAS precisa ter 64 caracteres hexadecimais');
    return Buffer.from(env, 'hex');
  }
  if (!fs.existsSync(CHAVE_FILE)) {
    fs.writeFileSync(CHAVE_FILE, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
    console.log('Chave das senhas criada em', CHAVE_FILE, '— faça uma cópia de segurança dela.');
  }
  const hex = fs.readFileSync(CHAVE_FILE, 'utf8').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('Arquivo de chave inválido: ' + CHAVE_FILE);
  return Buffer.from(hex, 'hex');
}
const CHAVE = carregarChave();
function cifrar(txt) {
  if (!txt) return null;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', CHAVE, iv);
  const enc = Buffer.concat([c.update(String(txt), 'utf8'), c.final()]);
  return ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), enc.toString('base64')].join(':');
}
function decifrar(s) {
  if (!s) return '';
  const [v, iv, tag, enc] = s.split(':');
  if (v !== 'v1') throw new Erro(500, 'Formato de senha desconhecido');
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', CHAVE, Buffer.from(iv, 'base64'));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(enc, 'base64')), d.final()]).toString('utf8');
  } catch {
    throw new Erro(500, 'Não foi possível abrir esta senha (a chave do servidor mudou?)');
  }
}

// primeiro acesso: cria o administrador
if (!db.prepare('SELECT COUNT(*) n FROM usuarios').get().n) {
  const senha = process.env.ADMIN_SENHA_INICIAL || 'rminfo';
  db.prepare('INSERT INTO usuarios (nome, login, senha_hash, perfil, pode_senhas) VALUES (?, ?, ?, ?, 1)')
    .run('Administrador', 'admin', hashSenha(senha), 'admin');
  console.log('Usuário admin criado.' + (process.env.ADMIN_SENHA_INICIAL ? '' : ' Senha inicial: rminfo (troque no primeiro acesso)'));
}

// ---------- dados do sistema ----------
const COLECOES = ['clientes', 'equipamentos', 'manutencoes', 'config'];
const ehAdmin = (u) => u.perfil === 'admin';
const podeSenhas = (u) => ehAdmin(u) || !!u.pode_senhas;
const podeGravar = (u, c) => ehAdmin(u) || c !== 'config';

const versaoAtual = () => db.prepare('SELECT COALESCE(MAX(versao), 0) v FROM registros').get().v;

function estado(desde) {
  const linhas = db.prepare('SELECT colecao, id, dados, apagado FROM registros WHERE versao > ? ORDER BY versao').all(desde);
  const itens = linhas.map((l) => (l.apagado ? { c: l.colecao, id: l.id, apagado: 1 } : { c: l.colecao, id: l.id, dados: JSON.parse(l.dados) }));
  return { versao: versaoAtual(), itens };
}

function sincronizar(u, ops) {
  if (!Array.isArray(ops)) throw new Erro(400, 'Formato inválido');
  if (ops.length > 5000) throw new Erro(413, 'Alterações demais de uma vez');
  return transacao(() => {
    let v = versaoAtual();
    const ler = db.prepare('SELECT dados, apagado FROM registros WHERE colecao = ? AND id = ?');
    const gravar = db.prepare(`INSERT INTO registros (colecao, id, dados, versao, apagado, usuario_id, atualizado_em)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'))
      ON CONFLICT(colecao, id) DO UPDATE SET dados = excluded.dados, versao = excluded.versao, apagado = excluded.apagado,
        usuario_id = excluded.usuario_id, atualizado_em = excluded.atualizado_em`);
    let recusados = 0;
    for (const op of ops) {
      const c = op && op.c, id = op && op.id;
      if (!COLECOES.includes(c) || typeof id !== 'string' || !id || id.length > 80) throw new Erro(400, 'Registro inválido');
      if (!podeGravar(u, c)) { recusados++; continue; }
      const linha = ler.get(c, id);
      if (op.apagar) {
        if (!linha || linha.apagado) continue;
        gravar.run(c, id, linha.dados, ++v, 1, u.id);
        continue;
      }
      const d = op.dados;
      if (!d || typeof d !== 'object' || Array.isArray(d) || d.id !== id) throw new Erro(400, 'Registro inválido');
      const json = JSON.stringify(d);
      if (json.length > 500000) throw new Erro(413, 'Registro muito grande');
      gravar.run(c, id, json, ++v, 0, u.id);
    }
    return { versao: v, recusados };
  });
}

// ---------- rotas ----------
const rotas = [];
function rota(metodo, caminho, handler, { admin = false, publica = false, senhas = false } = {}) {
  const nomes = [];
  const re = new RegExp('^' + caminho.replace(/:(\w+)/g, (_, n) => { nomes.push(n); return '(\\d+)'; }) + '$');
  rotas.push({ metodo, re, nomes, handler, admin, publica, senhas });
}
const ipDe = (req) => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;
const ehHttps = (req) => TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https';
const cookie = (req, valor, maxAge) =>
  `rmsid=${valor}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${ehHttps(req) ? '; Secure' : ''}`;

const MAX_FALHAS = 5, BLOQUEIO_MS = 15 * 60 * 1000;
const falhasLogin = new Map();
function conferirBloqueio(ip) {
  const f = falhasLogin.get(ip);
  if (f && f.n >= MAX_FALHAS && Date.now() - f.t < BLOQUEIO_MS) throw new Erro(429, 'Muitas tentativas. Aguarde 15 minutos e tente de novo.');
}
function registrarFalha(ip) {
  const f = falhasLogin.get(ip);
  const n = f && Date.now() - f.t < BLOQUEIO_MS ? f.n + 1 : 1;
  falhasLogin.set(ip, { n, t: Date.now() });
}
const publico = (u) => ({ id: u.id, nome: u.nome, login: u.login, perfil: u.perfil, pode_senhas: podeSenhas(u) ? 1 : 0 });

rota('POST', '/api/login', ({ req, body, res }) => {
  const ip = ipDe(req);
  conferirBloqueio(ip);
  const u = db.prepare('SELECT * FROM usuarios WHERE login = ? AND ativo = 1').get(String(body.login || '').trim());
  if (!u || !confereSenha(body.senha || '', u.senha_hash)) { registrarFalha(ip); throw new Erro(401, 'Usuário ou senha incorretos'); }
  falhasLogin.delete(ip);
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessoes (token, usuario_id) VALUES (?, ?)').run(token, u.id);
  res.setHeader('Set-Cookie', cookie(req, token, SESSAO_DIAS * 86400));
  return publico(u);
}, { publica: true });
rota('POST', '/api/logout', ({ req, token, res }) => {
  if (token) db.prepare('DELETE FROM sessoes WHERE token = ?').run(token);
  res.setHeader('Set-Cookie', cookie(req, '', 0));
}, { publica: true });
rota('GET', '/api/me', ({ user }) => publico(user));
rota('POST', '/api/me/senha', ({ body, user }) => {
  const u = db.prepare('SELECT senha_hash FROM usuarios WHERE id = ?').get(user.id);
  if (!confereSenha(body.atual || '', u.senha_hash)) throw new Erro(400, 'A senha atual está incorreta');
  db.prepare('UPDATE usuarios SET senha_hash = ? WHERE id = ?').run(hashSenha(validaSenha(body.nova)), user.id);
});

rota('GET', '/api/usuarios', () =>
  db.prepare('SELECT id, nome, login, perfil, pode_senhas, ativo, criado_em FROM usuarios ORDER BY ativo DESC, nome').all(), { admin: true });
rota('POST', '/api/usuarios', ({ body }) => {
  const nome = texto(body.nome, 80), login = texto(body.login, 30).toLowerCase();
  if (!nome || !/^[a-z0-9._-]{3,30}$/.test(login)) throw new Erro(400, 'Informe o nome e um usuário com 3 a 30 letras ou números, sem espaço');
  const perfil = body.perfil === 'admin' ? 'admin' : 'tecnico';
  if (db.prepare('SELECT 1 FROM usuarios WHERE login = ?').get(login)) throw new Erro(400, 'Esse usuário já existe');
  const r = db.prepare('INSERT INTO usuarios (nome, login, senha_hash, perfil, pode_senhas) VALUES (?, ?, ?, ?, ?)')
    .run(nome, login, hashSenha(validaSenha(body.senha)), perfil, body.pode_senhas ? 1 : 0);
  return { id: Number(r.lastInsertRowid) };
}, { admin: true });
rota('PUT', '/api/usuarios/:id', ({ body, params, user }) => {
  const alvo = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(params.id);
  if (!alvo) throw new Erro(404, 'Usuário não encontrado');
  const nome = texto(body.nome ?? alvo.nome, 80) || alvo.nome;
  const perfil = body.perfil === 'admin' ? 'admin' : body.perfil === 'tecnico' ? 'tecnico' : alvo.perfil;
  const ativo = body.ativo === undefined ? alvo.ativo : body.ativo ? 1 : 0;
  const ps = body.pode_senhas === undefined ? alvo.pode_senhas : body.pode_senhas ? 1 : 0;
  if (alvo.id === user.id && (perfil !== 'admin' || !ativo)) throw new Erro(400, 'Você não pode tirar o seu próprio acesso de administrador');
  db.prepare('UPDATE usuarios SET nome = ?, perfil = ?, ativo = ?, pode_senhas = ? WHERE id = ?').run(nome, perfil, ativo, ps, alvo.id);
  if (body.senha) db.prepare('UPDATE usuarios SET senha_hash = ? WHERE id = ?').run(hashSenha(validaSenha(body.senha)), alvo.id);
  if (!ativo || body.senha) db.prepare('DELETE FROM sessoes WHERE usuario_id = ?').run(alvo.id);
}, { admin: true });

rota('GET', '/api/estado', ({ query }) => estado(Math.max(0, Number(query.get('desde')) || 0)));
rota('POST', '/api/sync', ({ user, body }) => sincronizar(user, body.ops));

// ---------- cofre de senhas ----------
const TIPOS_CRED = ['wifi', 'equipamento', 'sistema', 'email', 'servidor', 'provedor', 'outro'];
function logSenha(req, user, cred, acao) {
  db.prepare('INSERT INTO log_senhas (credencial_id, titulo, usuario_id, usuario_nome, acao, ip) VALUES (?, ?, ?, ?, ?, ?)')
    .run(cred.id, cred.titulo, user.id, user.nome, acao, ipDe(req));
}
function lerCred(body) {
  const tipo = TIPOS_CRED.includes(body.tipo) ? body.tipo : 'outro';
  const titulo = texto(body.titulo, 120) || (tipo === 'wifi' && texto(body.ssid, 120)) || '';
  if (!titulo) throw new Erro(400, 'Informe uma descrição (ex.: "Roteador recepção" ou o nome da rede)');
  return {
    tipo, titulo,
    cliente_id: texto(body.cliente_id, 80) || null,
    equipamento_id: texto(body.equipamento_id, 80) || null,
    usuario: texto(body.usuario, 200), endereco: texto(body.endereco, 300), ssid: texto(body.ssid, 120), obs: texto(body.obs, 2000),
  };
}
const CAMPOS_CRED = 'id, cliente_id, equipamento_id, tipo, titulo, usuario, endereco, ssid, obs, (senha_enc IS NOT NULL) tem_senha, criado_em, atualizado_em';

rota('GET', '/api/credenciais', () => db.prepare(`SELECT ${CAMPOS_CRED} FROM credenciais ORDER BY titulo COLLATE NOCASE`).all(), { senhas: true });
rota('POST', '/api/credenciais', ({ req, body, user }) => {
  const c = lerCred(body);
  const r = db.prepare(`INSERT INTO credenciais (cliente_id, equipamento_id, tipo, titulo, usuario, endereco, ssid, obs, senha_enc, atualizado_por)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(c.cliente_id, c.equipamento_id, c.tipo, c.titulo, c.usuario, c.endereco, c.ssid, c.obs,
    cifrar(texto(body.senha, 500)), user.id);
  const id = Number(r.lastInsertRowid);
  logSenha(req, user, { id, titulo: c.titulo }, 'criou');
  return { id };
}, { senhas: true });
rota('PUT', '/api/credenciais/:id', ({ req, body, params, user }) => {
  const atual = db.prepare('SELECT * FROM credenciais WHERE id = ?').get(params.id);
  if (!atual) throw new Erro(404, 'Senha não encontrada');
  const c = lerCred(body);
  // senha: undefined = mantém, '' = apaga, texto = troca
  const senhaEnc = body.senha === undefined ? atual.senha_enc : cifrar(texto(body.senha, 500));
  db.prepare(`UPDATE credenciais SET cliente_id = ?, equipamento_id = ?, tipo = ?, titulo = ?, usuario = ?, endereco = ?, ssid = ?, obs = ?,
    senha_enc = ?, atualizado_em = datetime('now','localtime'), atualizado_por = ? WHERE id = ?`)
    .run(c.cliente_id, c.equipamento_id, c.tipo, c.titulo, c.usuario, c.endereco, c.ssid, c.obs, senhaEnc, user.id, atual.id);
  logSenha(req, user, atual, body.senha === undefined ? 'editou' : 'trocou a senha');
}, { senhas: true });
rota('DELETE', '/api/credenciais/:id', ({ req, params, user }) => {
  const atual = db.prepare('SELECT id, titulo FROM credenciais WHERE id = ?').get(params.id);
  if (!atual) throw new Erro(404, 'Senha não encontrada');
  db.prepare('DELETE FROM credenciais WHERE id = ?').run(atual.id);
  logSenha(req, user, atual, 'apagou');
}, { senhas: true });
rota('POST', '/api/credenciais/:id/revelar', ({ req, params, user }) => {
  const atual = db.prepare('SELECT id, titulo, senha_enc FROM credenciais WHERE id = ?').get(params.id);
  if (!atual) throw new Erro(404, 'Senha não encontrada');
  const senha = decifrar(atual.senha_enc);
  logSenha(req, user, atual, 'visualizou');
  return { senha };
}, { senhas: true });
rota('GET', '/api/credenciais/log', () =>
  db.prepare('SELECT * FROM log_senhas ORDER BY id DESC LIMIT 500').all(), { admin: true });

// ---------- servidor HTTP ----------
const TIPOS = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };

function lerCorpo(req) {
  return new Promise((resolve, reject) => {
    let d = '';
    req.on('data', (c) => { d += c; if (d.length > 10e6) { reject(new Erro(413, 'Requisição muito grande')); req.destroy(); } });
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch { reject(new Erro(400, 'JSON inválido')); } });
    req.on('error', reject);
  });
}
function lerToken(req) {
  const m = /(?:^|;\s*)rmsid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  return m ? m[1] : null;
}
const CABECALHOS = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' };
function enviarJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

const servidor = http.createServer(async (req, res) => {
  for (const [k, v] of Object.entries(CABECALHOS)) res.setHeader(k, v);
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) {
    try {
      const r = rotas.find((x) => x.metodo === req.method && x.re.test(url.pathname));
      if (!r) throw new Erro(404, 'Rota não encontrada');
      const m = r.re.exec(url.pathname);
      const params = Object.fromEntries(r.nomes.map((n, i) => [n, Number(m[i + 1])]));
      const token = lerToken(req);
      let user = null;
      if (token) {
        user = db.prepare(`SELECT u.id, u.nome, u.login, u.perfil, u.pode_senhas FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id
          WHERE s.token = ? AND u.ativo = 1 AND s.criado_em > datetime('now','localtime','-${SESSAO_DIAS} days')`).get(token) || null;
      }
      if (!r.publica && !user) throw new Erro(401, 'Faça login novamente');
      if (r.admin && !ehAdmin(user)) throw new Erro(403, 'Somente administrador');
      if (r.senhas && !podeSenhas(user)) throw new Erro(403, 'Você não tem permissão para ver as senhas');
      // proteção contra envio de formulário por outro site
      if (req.method !== 'GET' && req.headers['x-rm'] !== '1') throw new Erro(403, 'Requisição recusada');
      const body = ['POST', 'PUT'].includes(req.method) ? await lerCorpo(req) : {};
      const out = await r.handler({ req, res, body, params, query: url.searchParams, user, token });
      enviarJson(res, 200, out ?? { ok: true });
    } catch (e) {
      if (!e.status) console.error(e);
      enviarJson(res, e.status || 500, { erro: e.status ? e.message : 'Erro interno: ' + e.message });
    }
    return;
  }
  try {
    if (url.pathname.startsWith('/assets/')) {
      const arquivo = path.normalize(path.join(RAIZ, decodeURIComponent(url.pathname)));
      if (!arquivo.startsWith(path.join(RAIZ, 'assets')) || !fs.existsSync(arquivo) || fs.statSync(arquivo).isDirectory()) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': TIPOS[path.extname(arquivo)] || 'application/octet-stream', 'Cache-Control': 'public, max-age=86400' });
      return fs.createReadStream(arquivo).pipe(res);
    }
    res.writeHead(200, { 'Content-Type': TIPOS['.html'], 'Cache-Control': 'no-cache' });
    // index.html é o mesmo da demonstração; aqui ele recebe a marca que liga o modo online
    const html = fs.readFileSync(path.join(RAIZ, 'index.html'), 'utf8');
    res.end(html.replace('<script>', '<script>window.RM_ONLINE=1;</script>\n<script>'));
  } catch (e) {
    console.error(e);
    res.writeHead(500); res.end('Erro interno');
  }
});

// ---------- backup automático ----------
// Uma cópia por dia em dados/backups (guarda os últimos BACKUP_DIAS dias).
// As senhas continuam criptografadas no backup: para restaurar é preciso a mesma chave (chave-senhas.key).
function fazerBackup() {
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const destino = path.join(BACKUP_DIR, `rminfo-${fmtData(new Date())}.db`);
    if (!fs.existsSync(destino)) {
      db.exec(`VACUUM INTO '${destino.replace(/'/g, "''")}'`);
      console.log('Backup salvo:', destino);
    }
    const antigos = fs.readdirSync(BACKUP_DIR).filter((f) => /^rminfo-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort().reverse().slice(BACKUP_DIAS);
    for (const f of antigos) fs.unlinkSync(path.join(BACKUP_DIR, f));
    db.prepare(`DELETE FROM sessoes WHERE criado_em <= datetime('now','localtime','-${SESSAO_DIAS} days')`).run();
  } catch (e) {
    console.error('Falha no backup:', e.message);
  }
}
fazerBackup();
setInterval(fazerBackup, 3600e3).unref();

servidor.listen(PORT, HOST, () => {
  console.log(`\n  RM Informática rodando em: http://localhost:${PORT}\n`);
});
