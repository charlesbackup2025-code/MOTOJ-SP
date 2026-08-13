# Publicação do MotoJá SP

## Opção Docker

1. Copie `.env.example` para `.env`.
2. Troque `CORS_ORIGIN` pelo domínio HTTPS do app.
3. Execute `docker compose up -d --build`.
4. Coloque um proxy HTTPS (Caddy, Nginx ou o provedor de hospedagem) na frente da porta 8080.
5. Gere um par de chaves VAPID e preencha `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY` e `VAPID_SUBJECT` para habilitar Web Push.
6. Para pagamentos reais, configure `MP_ACCESS_TOKEN`, `MP_PUBLIC_KEY` e `MP_WEBHOOK_SECRET` do Mercado Pago; a confirmação só deve ocorrer pelo webhook assinado.

## Cuidados antes de produção

- trocar o armazenamento JSON por PostgreSQL;
- configurar HTTPS obrigatório;
- restringir `CORS_ORIGIN` a domínios conhecidos;
- adicionar expiração e revogação persistente de sessões;
- usar gateway de pagamento com webhook assinado;
- proteger endpoints com autenticação e limites de requisições;
- trocar obrigatoriamente o `ADMIN_TOKEN` de demonstração antes de publicar;
- configurar backups e logs sem dados sensíveis;
- manter a pasta de documentos fora de acesso público e adicionar antivírus/antimalware antes de aceitar arquivos reais;
- aplicar política de retenção e consentimento para documentos pessoais.
