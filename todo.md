# Scanner TODO

- [x] Corrigir HTTP 404 ao consultar o keys.json do GitHub no SV Android
- [x] Configurar o endpoint para https://raw.githubusercontent.com/silv7zzk/sv-keys/main/keys.json
- [x] Validar o catálogo e empacotar uma versão corrigida para Android

## Bug de compatibilidade

- [ ] Corrigir Keys geradas pelo painel que aparecem como inválidas no scanner
- [ ] Confirmar que normalização e SHA-256 são idênticos no painel e no SV Android
- [ ] Validar uma Key de teste sem publicar o valor original em arquivos públicos

## Bug de finalização

- [x] Fazer o scanner recusar explicitamente registros com finalizedAt ou status finalizada
- [x] Impedir autorização usando catálogo em cache quando a consulta atual ao GitHub falhar
- [x] Validar a invalidação imediata após finalizar uma Key e empacotar nova versão

## Novo bug reportado

- [ ] Corrigir Key recém-gerada pelo painel que aparece como inválida no scanner
- [ ] Confirmar que o hash publicado no keys.json usa a mesma normalização do scanner
- [ ] Validar publicação e leitura da nova Key sem expor o valor original
