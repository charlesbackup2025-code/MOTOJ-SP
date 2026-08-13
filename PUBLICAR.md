# Publicar online

O projeto está pronto para ser publicado, mas ainda é necessário conectar uma conta de hospedagem. Não coloque segredos no código.

## Render

1. Crie um serviço Web a partir deste diretório.
2. Use o `render.yaml` como blueprint.
3. Preencha as variáveis secretas no painel.
4. Aponte `CORS_ORIGIN` para o domínio HTTPS criado.
5. Configure no Mercado Pago o webhook `https://SEU_DOMINIO/api/webhooks/mercadopago`.

## Fly.io

1. Instale o Fly CLI e faça login.
2. Troque `app = 'motoja-sp'` por um nome disponível.
3. Crie o volume `motoja_data` na região `gru`.
4. Configure os secrets com `fly secrets set`.
5. Execute `fly deploy`.

## Domínio próprio

Aponte o DNS para o provedor escolhido e mantenha HTTPS obrigatório. Depois atualize `CORS_ORIGIN`, `VAPID_SUBJECT` e os endereços de retorno do gateway.
