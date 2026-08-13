# MotoJá SP para Android

Projeto Android nativo que empacota o PWA MotoJá SP em WebView.

O workflow `.github/workflows/android-apk.yml` gera automaticamente `app-debug.apk` e publica como artefato do GitHub Actions a cada alteração em `android/`.

O APK debug é próprio para testes. Para publicar na Play Store, ainda é necessário criar uma chave de assinatura, gerar um AAB release e preencher as informações da loja.
