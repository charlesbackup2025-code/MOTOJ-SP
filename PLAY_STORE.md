# Publicação na Google Play

O workflow atual gera o APK debug e também o AAB release sem assinatura. Para publicar na Play Store:

1. Crie uma keystore e guarde uma cópia offline.
2. Configure `storeFile`, `storePassword`, `keyAlias` e `keyPassword` como secrets do GitHub Actions.
3. Adicione um `signingConfig` de release no `android/app/build.gradle` sem colocar senhas no repositório.
4. Gere o `app-release.aab` assinado.
5. Cadastre o app no Google Play Console e faça o upload do AAB.

O APK debug continua disponível para testes diretos no celular.
