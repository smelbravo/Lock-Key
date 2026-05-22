# Lock & Key — Gestor de Passwords Seguro

**Lock & Key** é um gestor de passwords de arquitetura **zero-knowledge** com encriptação **AES-256-GCM**, construído com PHP 8+, MySQL e JavaScript nativo. Inclui um Painel de Admin com controlo de acessos por roles, gerador de passwords dedicado e uma extensão Firefox com autofill automático.

**URL local:** `http://localhost/Lock%26Key/frontend/`

## Estrutura do Projeto

```
Lock&Key/
├── backend/                    # API REST em PHP
│   ├── api/
│   │   ├── auth/               # Autenticação (login, registo, logout, refresh, get_salt)
│   │   ├── vault/              # Gestão do cofre (CRUD + exportar)
│   │   ├── notes/              # Notas seguras (CRUD)
│   │   ├── user/               # Perfil, alterar senha, eliminar conta
│   │   └── admin/              # Endpoints do painel Admin
│   ├── config/                 # Configuração e ligação à BD
│   ├── helpers/                # JWT, encriptação, respostas
│   ├── middleware/             # Autenticação JWT, rate limiting
│   ├── bootstrap.php           # Bootstrap central
│   └── .htaccess               # Segurança Apache
├── config/
│   ├── .env                    # Variáveis de ambiente (NÃO fazer commit)
│   └── .env.example            # Template de configuração
├── database/
│   ├── schema.sql              # Schema MySQL completo
│   └── migration_roles.sql     # Migração: roles e planos de subscrição
├── setup/
│   └── create_admin.php        # Script para criar conta admin inicial
├── extension/                  # Extensão Firefox
│   ├── manifest.json           # Manifest V2 (ícones SVG)
│   ├── popup/                  # Interface do popup (popup.html + popup.js)
│   ├── background/             # Background script
│   ├── content/                # Content script (autofill)
│   └── assets/                 # Ícone SVG da extensão
└── frontend/                   # Website completo
    ├── index.html              # Landing page pública
    ├── login.html              # Login
    ├── register.html           # Registo
    ├── dashboard.html          # Dashboard principal
    ├── vault.html              # Cofre de passwords
    ├── notes.html              # Notas seguras
    ├── generator.html          # Gerador de passwords (página dedicada)
    ├── settings.html           # Definições da conta
    ├── admin.html              # Painel Admin (só Admins)
    ├── css/
    │   ├── variables.css       # Tokens de design global
    │   ├── main.css            # Estilos globais e páginas públicas
    │   ├── auth.css            # Estilos de login/registo
    │   ├── dashboard.css       # Layout do dashboard (grid, sidebar, header)
    │   └── admin.css           # Estilos do painel Admin
    └── js/
        ├── crypto.js           # Criptografia client-side (PBKDF2, AES-GCM)
        ├── api.js              # Comunicação com a API REST
        ├── auth.js             # Lógica de login, registo e requireAuth()
        ├── utils.js            # Utilitários, tema, auto-lock, layout sidebar
        ├── dashboard.js        # Dashboard principal
        ├── vault.js            # Gestão do cofre
        ├── notes.js            # Gestão de notas seguras
        ├── generator.js        # Lógica do gerador de passwords
        ├── settings.js         # Definições da conta
        └── admin.js            # Painel Admin
```

## Arquitetura de Segurança Zero-Knowledge

```
Senha Mestra (nunca sai do browser)
        ↓
PBKDF2-SHA256 (200.000 iterações) + vault_salt gerado no CLIENTE
        ↓ 512 bits
┌──────────────────┬─────────────────────────────────────┐
│  authKey (256b)  │       encryptionKey (256b)           │
│  Enviado p/ API  │  Fica em memória/sessionStorage      │
│  Hash Argon2id   │  Encripta todos os dados do cofre    │
└──────────────────┴─────────────────────────────────────┘
```

**Princípios Zero-Knowledge:**

- O `vault_salt` é gerado **no cliente** no momento do registo e enviado ao servidor para armazenamento — o servidor nunca gera o seu próprio salt
- O servidor **nunca vê**: senha mestra, `encryptionKey`, dados em texto simples
- **Encriptação**: AES-256-GCM com IV único por entrada
- **Autenticação**: Argon2id para hash do `authKey`
- **Tokens**: JWT (HS256) com `role`, `plan` e `status` + refresh token com rotação
- **Rate limiting**: proteção contra brute force por IP e email
- **Auto-lock**: sessão bloqueada por inatividade (30 min, configurável)
- **Persistência de sessão**: `encryptionKey` raw bytes guardados em `sessionStorage` para sobreviver a navegação entre páginas sem pedir senha mestra

### Cópia de segurança, importação e eliminação de conta

- **Exportar cofre** (`GET /vault/export.php`): devolve JSON com `export_version`, `user_uuid`, `entries` e `notes` ainda encriptados (o servidor não desencripta).
- **Importar** (página Definições): carregar o `.json` exportado; só é permitido se o campo `user_uuid` do ficheiro for o da conta com sessão iniciada — *ciphertext* de outra conta não pode ser importado. Em backups muito antigos sem `user_uuid`, é feita uma verificação de desencriptação com a chave de sessão do cofre (é preciso ter o cofre desbloqueado). Cada item importado cria **novos** registos (novos UUIDs). A importação para se atingires o limite do plano.
- **Eliminar conta** (`POST /user/delete_account.php`): envia-se o `auth_key` (hex 64) derivado da senha mestra; remove a conta e dados associados (cascade na BD). O único utilizador `admin_master` do sistema **não** pode eliminar-se a si próprio.

## Roles e Planos

### Roles de utilizador

| Role | Descrição |
|------|-----------|
| `user` | Utilizador normal (padrão ao registar) |
| `admin` | Acesso ao painel Admin (gestão de utilizadores, audit log) |
| `admin_master` | Acesso total: pode criar/gerir Admins e alterar roles/planos |

### Planos de subscrição

| Plano | Passwords | Notas | Funcionalidades |
|-------|-----------|-------|-----------------|
| `free` | 50 | 10 | Básico |
| `pro` | 500 | 100 | Histórico, exportar |
| `unlimited` | Ilimitado | Ilimitado | Tudo |

## Instalação Local (XAMPP)

### 1. Instalar XAMPP

1. Descarrega XAMPP em [apachefriends.org](https://www.apachefriends.org)
2. Instala em `C:\xampp`
3. Abre o **XAMPP Control Panel**
4. Inicia os módulos **Apache** e **MySQL**

### 2. Copiar o Projeto

Copia a pasta `Lock&Key` (com o `&` no nome) para:

```
C:\xampp\htdocs\Lock&Key\
```

**Nota:** Manter o `&` no nome da pasta — o URL usa `Lock%26Key` (codificação URL do `&`).

### 3. Configurar a Base de Dados

1. Abre `http://localhost/phpmyadmin`
2. Cria nova base de dados: nome `lockandkey`, cotejamento `utf8mb4_unicode_ci`
3. Seleciona a base de dados → **Importar**
4. Importa: `database/schema.sql`
5. Importa também: `database/migration_roles.sql` *(adiciona roles e planos)*

### 4. Configurar o Ambiente

1. Copia `config/.env.example` para `config/.env`
2. Edita `config/.env`:

```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=lockandkey
DB_USER=root
DB_PASS=           # deixar vazio se XAMPP não tiver senha

APP_URL=http://localhost/Lock%26Key/frontend
API_URL=http://localhost/Lock%26Key/backend/api

# Gerar valores únicos:
JWT_SECRET=<string hexadecimal de 128 caracteres>
SERVER_ENCRYPT_KEY=<string hexadecimal de 64 caracteres>
```

Gerar `JWT_SECRET` em PHP: `echo bin2hex(random_bytes(64));`

### 5. Criar Conta Admin

Abre o browser em:

```
http://localhost/Lock%26Key/setup/create_admin.php
```

Segue o formulário para criar a primeira conta `admin_master`. Após criar, **apaga ou protege** este ficheiro.

O script `create_admin.php` usa o mesmo fluxo zero-knowledge do frontend: gera um `vault_salt` internamente e deriva o `authKey` com PBKDF2, garantindo que o login funciona corretamente.

### 6. Configurar Apache

Confirma que o `AllowOverride All` está ativo em `C:\xampp\apache\conf\httpd.conf`:

```apache
<Directory "C:/xampp/htdocs">
    AllowOverride All
</Directory>
```

Reinicia o Apache após alterar.

### 7. Aceder ao Website

```
http://localhost/Lock%26Key/frontend/
```

## Painel Admin

Acessível em `/frontend/admin.html` — **apenas para utilizadores com role `admin` ou `admin_master`**.

O link "Painel Admin" aparece automaticamente na sidebar para Admins após login.

### Funcionalidades do Painel Admin

| Secção | admin | admin_master |
|--------|-------|--------------|
| Visão geral (estatísticas) | Sim | Sim |
| Listar utilizadores | Sim | Sim |
| Ver audit log | Sim | Sim |
| Suspender/ativar utilizadores | Sim | Sim |
| Alterar plano de utilizador | Não | Sim |
| Alterar role de utilizador | Não | Sim |
| Criar conta admin | Não | Sim |

## Gerador de Passwords

Página dedicada em `/frontend/generator.html`.

- Comprimento configurável (8–128 caracteres)
- Tipos de caracteres: maiúsculas, minúsculas, números, símbolos
- Exclusão de caracteres ambíguos (0, O, 1, l, I)
- Indicador de força em tempo real
- Histórico da sessão (últimas 20 passwords geradas)
- Botão de copiar para a área de transferência

## Extensão Firefox

### Instalar (modo temporário para testes)

1. Abre Firefox → `about:debugging`
2. Clica em **"This Firefox"**
3. Clica em **"Load Temporary Add-on..."**
4. Seleciona `extension/manifest.json`

### Funcionalidades

- Login com email e senha mestra
- **Sessão persistente**: a sessão é guardada em `browser.storage.local` — não é necessário fazer login novamente ao reabrir o popup
- Listagem e pesquisa de entradas do cofre
- Autofill automático em formulários de login
- Guardar novas credenciais ao submeter formulários
- Adicionar/editar entradas diretamente no popup

### Empacotar para distribuição

```powershell
# Windows (PowerShell)
Compress-Archive -Path "extension\*" -DestinationPath "lockandkey-extension-v1.0.zip"
```

Submeter em: https://addons.mozilla.org/developers/

## Endpoints da API

### Autenticação

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/auth/get_salt.php` | Obter vault_salt do utilizador |
| POST | `/auth/register.php` | Registar conta (requer `vault_salt` do cliente) |
| POST | `/auth/login.php` | Iniciar sessão |
| POST | `/auth/logout.php` | Terminar sessão |
| POST | `/auth/refresh.php` | Renovar access token |

### Cofre

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET  | `/vault/entries.php` | Listar entradas |
| POST | `/vault/create.php` | Criar entrada |
| POST | `/vault/update.php` | Atualizar entrada |
| POST | `/vault/delete.php` | Eliminar entrada |
| GET  | `/vault/export.php` | Exportar cofre encriptado |

### Notas

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET  | `/notes/notes.php` | Listar notas |
| POST | `/notes/create.php` | Criar nota |
| POST | `/notes/update.php` | Atualizar nota |
| POST | `/notes/delete.php` | Eliminar nota |

### Utilizador

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET  | `/user/profile.php` | Obter perfil (inclui role, plan, status) |
| POST | `/user/profile.php` | Atualizar perfil |
| POST | `/user/change_password.php` | Alterar senha mestra |
| POST | `/user/delete_account.php` | Eliminar a própria conta (`auth_key` hex 64) |

### Admin *(requer role admin ou admin_master)*

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET  | `/admin/stats.php` | Estatísticas globais |
| GET  | `/admin/users.php` | Listar utilizadores |
| POST | `/admin/users.php` | Atualizar utilizador (role, plano, status) |
| GET  | `/admin/audit.php` | Ver audit log |
| POST | `/admin/create_admin.php` | Criar conta admin |

## Deploy em Produção

### Requisitos do Servidor

- PHP 8.1+ com extensões: `openssl`, `pdo_mysql`, `mbstring`
- MySQL 8.0+ ou MariaDB 10.5+
- Apache 2.4+ com `mod_rewrite` e `mod_headers`
- HTTPS obrigatório (certificado SSL)

### Passos de Deploy

```bash
# Clonar projeto
git clone https://github.com/smelbravo/Lock-Key /var/www/lockandkey

# Configurar permissões
chmod -R 644 /var/www/lockandkey
chmod -R 755 /var/www/lockandkey/backend
find /var/www/lockandkey -type d -exec chmod 755 {} \;
chmod 600 /var/www/lockandkey/config/.env
```

### .env para Produção

```env
APP_ENV=production
APP_URL=https://tuaapp.com
API_URL=https://tuaapp.com/api

DB_HOST=localhost
DB_NAME=lockandkey
DB_USER=lockandkey_user
DB_PASS=<senha_forte_BD>

JWT_SECRET=<novo_128_hex>
SERVER_ENCRYPT_KEY=<novo_64_hex>
```

### Checklist de Segurança

- [ ] HTTPS configurado e certificado SSL válido
- [ ] `.env` não acessível via web (`curl -I https://tuaapp.com/config/.env` deve dar 403)
- [ ] `setup/create_admin.php` removido após criar conta admin
- [ ] `APP_ENV=production` (desativa debug)
- [ ] Backups automáticos da base de dados
- [ ] Rate limiting ativo
- [ ] Headers de segurança HTTP verificados (https://securityheaders.com)
- [ ] `expose_php = Off` no php.ini
- [ ] `display_errors = Off` no php.ini
- [ ] Utilizador da BD com permissões mínimas (SELECT, INSERT, UPDATE, DELETE apenas)
- [ ] Porta 3306 não exposta publicamente
- [ ] Monitorização de logs de erro ativa

## Resolução de Problemas

### "Credenciais inválidas" após criar conta nova

O registo usa arquitetura zero-knowledge: o `vault_salt` é gerado no cliente e enviado ao servidor. Contas criadas com versões antigas do código (que usavam salt temporário descartado) não conseguem fazer login — precisam de ser recriadas.

### "Não consegue ligar à base de dados"

- Verifica que o MySQL está a correr no XAMPP
- Verifica as credenciais em `config/.env`
- Confirma que a base de dados `lockandkey` existe e que `migration_roles.sql` foi importada

### "Token JWT inválido"

- `JWT_SECRET` no `.env` deve ter pelo menos 64 caracteres
- O relógio do servidor deve estar sincronizado

### Extensão pede login ao reabrir popup

- Confirma que `browser.storage.local` tem permissão no `manifest.json`
- A sessão é guardada com a chave `rawKey` — versões antigas que usavam `encKey` perdiam sempre a sessão

### "CORS Error na API"

- Verifica `CORS_ALLOWED_ORIGINS` no `.env`
- Confirma que `APP_URL` corresponde ao URL da página no browser

### Dropdown de utilizador não abre

- Atualiza os ficheiros no htdocs — versões antigas tinham `overflow:hidden` no layout que bloqueava o menu

### UI cortada pela barra de bookmarks do Firefox

- O CSS usa `100dvh` (dynamic viewport height) que exclui a barra de bookmarks automaticamente
- Confirma que estás a usar os ficheiros CSS mais recentes

## Licença

MIT License — Lock & Key © 2026
