# MotoJá SP — MVP v2

Protótipo de PWA para validar o fluxo de corridas de moto em São Paulo.

## O que já funciona
- Perfil local de passageiro/motociclista.
- Solicitação com origem, destino e distância.
- Estimativa de preço e tempo.
- Preenchimento da localização do aparelho, quando permitido.
- Modo motociclista online, aceite e recusa.
- Histórico de viagens concluídas.
- Cache offline e instalação como PWA quando servido em HTTPS.
- Mapa com Leaflet/OpenStreetMap e localização do aparelho.
- Rastreamento do motociclista enquanto está online.
- Seleção de Pix, cartão de demonstração ou dinheiro.
- Avaliação de 1 a 5 estrelas após a corrida.
- Alertas do navegador para mudanças de status.

## Como testar
1. Extraia o arquivo.
2. Sirva a pasta `motoja-sp` em um servidor HTTPS ou ambiente local de desenvolvimento.
3. Abra `index.html` no navegador.
4. Crie um perfil, solicite uma corrida e alterne para o modo Motociclista para aceitar.

## Backend incluído nesta versão

O arquivo `server.py` traz uma API de desenvolvimento sem dependências externas. Ela usa SQLite por padrão (`motoja.sqlite3`) e oferece:

- `GET /api/health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/profiles`
- `POST /api/profiles`
- `GET /api/push/config`
- `POST /api/profiles/{id}/push-subscription`
- `GET /api/payments/config`
- `POST /api/rides`
- `POST /api/rides/{id}/payment`
- `POST /api/webhooks/mercadopago`
- `GET /api/rides?status=searching`
- `POST /api/rides/{id}/accept`
- `POST /api/rides/{id}/location`
- `POST /api/rides/{id}/cancel`
- `POST /api/rides/{id}/finish`
- `POST /api/rides/{id}/rating`
- `POST /api/rides/{id}/report`
- `POST /api/rides/{id}/emergency`
- `GET /api/admin/stats`
- `GET /api/admin/rides`
- `GET /api/admin/profiles`
- `GET /api/admin/documents/{id}`
- `POST /api/admin/profiles/{id}/verification`

Para iniciar: `python3 server.py` e abra `http://localhost:8080`. Também incluí `Dockerfile`, `docker-compose.yml`, `.env.example`, `DEPLOY.md`, `PUBLICAR.md`, `render.yaml`, `fly.toml`, `Caddyfile` e `nginx.conf` para publicação online. O painel administrativo fica em `admin.html` e usa o `ADMIN_TOKEN` configurado no ambiente. Ele também permite aprovar ou reprovar cadastros de motociclistas; só perfis aprovados podem ficar online. Motociclistas podem enviar até dois documentos em imagem ou PDF, com limite de 5 MB cada, e a aprovação exige dois documentos.

A interface tenta sincronizar automaticamente com essa API e continua funcionando em modo local quando o servidor não está disponível. Para testar entre aparelhos na mesma rede, publique o servidor em um endereço acessível por eles. A versão possui cadastro/login com PIN protegido por PBKDF2, token de sessão em memória, persistência SQLite, relatos de problemas, suspensão automática após três denúncias ou média inferior a 2,5 depois de cinco avaliações, botão SOS, compartilhamento da corrida, alerta de velocidade incompatível e infraestrutura de Web Push com VAPID. Para push real, preencha as chaves VAPID no `.env`. O gateway Mercado Pago fica em modo demonstração sem `MP_ACCESS_TOKEN`; com as credenciais configuradas, o backend cria Pix real e checkout para cartão. Ainda faltam webhooks assinados, PostgreSQL gerenciado, recuperação de conta, expiração de sessão e proteções de produção.
