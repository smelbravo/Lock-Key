# 🔐 Lock & Key — Gestor de Passwords Seguro

**Lock & Key** é um gestor de passwords de arquitetura **zero-knowledge** com encriptação **AES-256-GCM**, construído com PHP 8+, MySQL e JavaScript nativo. Inclui uma extensão Firefox com autofill automático.

---

## 📁 Estrutura do Projeto

```
Lock&Key/
├── backend/                    # API REST em PHP
│   ├── api/
│   │   ├── auth/               # Autenticação (login, registo, logout, refresh, get_salt)
│   │   ├── vault/              # Gestão do cofre (CRUD + exportar)
│   │   ├── notes/              # Notas seguras (CRUD)
│   │   └── user/               # Perfil e alterar senha
│   ├── config/                 # Configuração e ligação à BD
│   ├── helpers/                # JWT, encriptação, respostas
│   ├── middleware/             # Autenticação JWT, rate limiting
│   ├── bootstrap.php           # Bootstrap central
│   └── .htaccess               # Segurança Apache
├── config/
│   ├── .env                    # Variáveis de ambiente (NÃO fazer commit)
│   └── .env.example            # Template de configuração
├── database/
│   └── schema.sql              # Schema MySQL completo
├── extension/                  # Extensão Firefox
│   ├── manifest.json           # Manifest V2
│   ├── popup/                  # Interface do popup
│   ├── background/             # Background script
│   ├── content/                # Content script (autofill)
│   └── assets/                 # Ícones da extensão
└── frontend/                   # Website completo
    ├── index.html              # Landing page
    ├── login.html              # Login
    ├── register.html           # Registo
    ├── dashboard.html          # Dashboard principal
    ├── vault.html              # Gestor de passwords
    ├── notes.html              # Notas seguras
    ├── settings.html           # Definições
    ├── css/                    # Estilos (variables, main, auth, dashboard)
    └── js/                     # Lógica (crypto, api, auth, vault, notes, etc.)
```

---

## 🔒 Arquitetura de Segurança Zero-Knowledge

```
Senha Mestra (nunca sai do browser)
        ↓
PBKDF2-SHA256 (200.000 iterações) + salt único por conta
        ↓ 512 bits
┌──────────────────┬─────────────────────────────────────┐
│  authKey (256b)  │       encryptionKey (256b)           │
│  Enviado p/ API  │  Fica em memória no browser          │
│  Hash Argon2id   │  Encripta todos os dados do cofre    │
└──────────────────┴─────────────────────────────────────┘
```

- **O servidor NUNCA vê**: senha mestra, encryptionKey, dados em texto simples
- **Encriptação**: AES-256-GCM com IV único por entrada
- **Autenticação**: Argon2id para hash do authKey
- **Tokens**: JWT (HS256) + refresh token com rotação
- **Rate limiting**: proteção contra brute force por IP e email
- **Auto-logout**: sessão bloqueada por inatividade (30 min padrão)

---

## ⚙️ Instalação Local (XAMPP)

### 1. Instalar XAMPP

1. Descarrega XAMPP em [apachefriends.org](https://www.apachefriends.org)
2. Instala em `C:\xampp` (ou o caminho padrão)
3. Abre o **XAMPP Control Panel**
4. Inicia os módulos **Apache** e **MySQL**

### 2. Copiar o Projeto

Copia a pasta `Lock&Key` para o diretório raiz do XAMPP:
```
C:\xampp\htdocs\lockandkey\
```

A estrutura final deve ser:
```
C:\xampp\htdocs\lockandkey\
    ├── backend\
    ├── config\
    ├── database\
    ├── extension\
    └── frontend\
```

### 3. Configurar a Base de Dados

1. Abre o browser em: `http://localhost/phpmyadmin`
2. Clica em **"Nova"** (criar nova base de dados)
3. Nome: `lockandkey`, Cotejamento: `utf8mb4_unicode_ci`
4. Clica em **"Importar"** → **"Escolher ficheiro"**
5. Seleciona: `C:\xampp\htdocs\lockandkey\database\schema.sql`
6. Clica em **"Executar"**

Ou via linha de comandos:
```bash
mysql -u root -p < database\schema.sql
```

### 4. Configurar o Ambiente

1. Copia `config\.env.example` para `config\.env`
2. Abre `config\.env` e configura:

```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=lockandkey
DB_USER=root
DB_PASS=           # deixar vazio se XAMPP não tiver senha

# IMPORTANTE: Gerar valores únicos para produção
JWT_SECRET=<string hexadecimal de 128 caracteres>
SERVER_ENCRYPT_KEY=<string hexadecimal de 64 caracteres>
```

> **Para gerar JWT_SECRET em PHP:**
> ```php
> echo bin2hex(random_bytes(64));
> ```
> **Ou online em**: https://generate-random.org/string-generator

### 5. Configurar Apache (opcional)

Se o teu XAMPP tiver a opção `AllowOverride All`, os ficheiros `.htaccess` funcionam automaticamente.

Se não, abre `C:\xampp\apache\conf\httpd.conf` e procura:
```apache
<Directory "C:/xampp/htdocs">
    AllowOverride None
```
Muda para:
```apache
<Directory "C:/xampp/htdocs">
    AllowOverride All
```
Reinicia o Apache.

### 6. Aceder ao Website

Abre o browser Firefox e vai a:
```
http://localhost/Lock&Key/frontend/
```

---

## 🧪 Testar a API

### Usando o Browser (Firefox Developer Tools)

Abre a consola (F12) e testa:

```javascript
// 1. Obter salt (passo 1 do login)
fetch('http://localhost/lockandkey/backend/api/auth/get_salt.php', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'teste@exemplo.com' })
}).then(r => r.json()).then(console.log);
```

### Usando cURL (linha de comandos)

```bash
# Registar utilizador
curl -X POST http://localhost/lockandkey/backend/api/auth/register.php \
  -H "Content-Type: application/json" \
  -d '{"email":"teste@exemplo.pt","username":"utilizador_teste","auth_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'

# Login (substitui auth_key pelo valor derivado pelo PBKDF2 no cliente)
curl -X POST http://localhost/lockandkey/backend/api/auth/login.php \
  -H "Content-Type: application/json" \
  -d '{"email":"teste@exemplo.pt","auth_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
```

> **Nota**: O `auth_key` real é gerado pelo browser via PBKDF2. Nas ferramentas de developer do browser, podes testar o fluxo completo.

---

## 🦊 Instalar a Extensão Firefox

### Método 1: Temporário (para testes)

1. Abre Firefox
2. Vai a `about:debugging`
3. Clica em **"This Firefox"** (Este Firefox)
4. Clica em **"Load Temporary Add-on..."** (Carregar Extensão Temporária)
5. Navega até `Lock&Key\extension\`
6. Seleciona o ficheiro `manifest.json`
7. A extensão aparece na barra de ferramentas

### Método 2: Permanente (signed)

Para instalar permanentemente é necessário:
1. Criar uma conta em https://addons.mozilla.org
2. Submeter a extensão para revisão
3. Ou usar Firefox Developer Edition / Nightly (que permite extensões não assinadas)

### Testar a Extensão

1. **Popup**: Clica no ícone 🔐 na barra do Firefox
2. **Login**: Introduz o email e senha mestra
3. **Autofill**: Vai a qualquer site com formulário de login
4. **Guardar**: Submete um formulário → aparece notificação para guardar

### Testar o Autofill

1. Vai a um site de login (ex: `http://localhost/teste-login.html`)
2. Clica no campo de password
3. Aparece um ícone 🔐 ao lado do campo
4. Clica no ícone → popup abre
5. Seleciona a entrada correta → campos preenchidos automaticamente

---

## 📦 Empacotar a Extensão para Distribuição

```bash
# Criar ZIP da extensão
cd extension
zip -r ../lockandkey-extension-v1.0.zip . -x "*.DS_Store" "*.gitignore"
```

Ou no Windows (PowerShell):
```powershell
Compress-Archive -Path "extension\*" -DestinationPath "lockandkey-extension-v1.0.zip"
```

Para submeter ao Mozilla Add-ons: https://addons.mozilla.org/developers/

---

## 🚀 Deploy em Produção

### Requisitos do Servidor

- PHP 8.1+ com extensões: `openssl`, `pdo_mysql`, `mbstring`
- MySQL 8.0+ ou MariaDB 10.5+
- Apache 2.4+ com `mod_rewrite` e `mod_headers`
- HTTPS obrigatório (certificado SSL)

### Passos de Deploy

#### 1. Servidor Web (Apache/Nginx)

```bash
# Clonar projeto no servidor
git clone <repo> /var/www/lockandkey

# Configurar permissões
chmod -R 644 /var/www/lockandkey
chmod -R 755 /var/www/lockandkey/backend
find /var/www/lockandkey -type d -exec chmod 755 {} \;
```

#### 2. Configurar .env para Produção

```env
APP_ENV=production
APP_URL=https://tuaapp.com
API_URL=https://tuaapp.com/api

DB_HOST=localhost
DB_NAME=lockandkey
DB_USER=lockandkey_user
DB_PASS=<senha_forte_BD>

JWT_SECRET=<gerar_novo_128_hex>
SERVER_ENCRYPT_KEY=<gerar_novo_64_hex>
```

#### 3. Proteger ficheiros sensíveis

```bash
# .env nunca deve ser acessível via web
chmod 600 /var/www/lockandkey/config/.env

# Verificar que o .htaccess está a bloquear acesso
curl -I https://tuaapp.com/config/.env
# Deve retornar 403 Forbidden
```

#### 4. Base de Dados em Produção

```sql
-- Criar utilizador com permissões mínimas
CREATE USER 'lockandkey_user'@'localhost' IDENTIFIED BY 'senha_forte';
GRANT SELECT, INSERT, UPDATE, DELETE ON lockandkey.* TO 'lockandkey_user'@'localhost';
FLUSH PRIVILEGES;
```

#### 5. SSL/HTTPS

Usar Let's Encrypt (gratuito):
```bash
certbot --apache -d tuaapp.com
```

#### 6. Configurar CRON para limpeza periódica

```bash
# Adicionar ao crontab (executar diariamente às 3h)
0 3 * * * mysql -u lockandkey_user -p<senha> lockandkey -e "CALL cleanup_expired_data();"
```

#### 7. Headers de Segurança Adicionais (nginx)

```nginx
server {
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    # Clickjacking protection
    add_header X-Frame-Options "DENY" always;
    # XSS protection
    add_header X-XSS-Protection "1; mode=block" always;
    # Content type sniffing
    add_header X-Content-Type-Options "nosniff" always;
}
```

### Checklist de Segurança para Produção

- [ ] HTTPS configurado e certificado SSL válido
- [ ] `.env` não acessível via web (teste com curl)
- [ ] Passwords do .env diferentes das de desenvolvimento
- [ ] `APP_ENV=production` (desativa debug)
- [ ] Backups automáticos da base de dados configurados
- [ ] Rate limiting ativo
- [ ] Headers de segurança HTTP verificados (https://securityheaders.com)
- [ ] `expose_php = Off` no php.ini
- [ ] `display_errors = Off` no php.ini
- [ ] Utilizador da BD com permissões mínimas
- [ ] Firewall configurada (porta 3306 não exposta publicamente)
- [ ] Monitorização de logs de erro ativa
- [ ] Cron de limpeza configurado

---

## 🔧 Resolução de Problemas

### "Não consegue ligar à base de dados"
- Verifica que o MySQL está a correr no XAMPP
- Verifica as credenciais em `config/.env`
- Testa a ligação: `mysql -u root -p -h 127.0.0.1`

### "Token JWT inválido"
- Verifica que `JWT_SECRET` no `.env` tem pelo menos 64 caracteres
- Verifica que o relógio do servidor está sincronizado (importante para JWT)

### "Extensão não autofill"
- Verifica que o website usa HTTPS ou localhost
- Abre a consola da extensão em `about:debugging` → Inspect
- Verifica permissões no `manifest.json`

### "CORS Error na API"
- Verifica `CORS_ALLOWED_ORIGINS` no `.env`
- Verifica que o `APP_URL` corresponde ao URL da página

---

## 📖 Endpoints da API

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/auth/get_salt.php` | Obter salt PBKDF2 |
| POST | `/auth/register.php` | Registar conta |
| POST | `/auth/login.php` | Iniciar sessão |
| POST | `/auth/logout.php` | Terminar sessão |
| POST | `/auth/refresh.php` | Renovar token |
| GET  | `/vault/entries.php` | Listar entradas |
| POST | `/vault/create.php` | Criar entrada |
| POST | `/vault/update.php` | Atualizar entrada |
| POST | `/vault/delete.php` | Eliminar entrada |
| GET  | `/vault/export.php` | Exportar cofre |
| GET  | `/notes/notes.php` | Listar notas |
| POST | `/notes/create.php` | Criar nota |
| POST | `/notes/update.php` | Atualizar nota |
| POST | `/notes/delete.php` | Eliminar nota |
| GET  | `/user/profile.php` | Obter perfil |
| POST | `/user/profile.php` | Atualizar perfil |
| POST | `/user/change_password.php` | Alterar senha |

---

## 📜 Licença

MIT License — Lock & Key © 2026
