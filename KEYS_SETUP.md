# Sistema de Keys via GitHub

## Visão geral

O login não usa mais a senha fixa `SVADM`. O navegador baixa um catálogo JSON publicado em um repositório GitHub, calcula o SHA-256 da Key digitada e compara somente com o campo `hash` do catálogo. Assim, as Keys em texto puro não precisam ser armazenadas no repositório.

> O catálogo deve ser público para que o navegador consiga consultá-lo sem token. Não coloque tokens, senhas, dados pessoais ou segredos no repositório.

## Planos e validade

| Plano | Duração calculada |
|---|---:|
| `diaria` | 1 dia corrido, ou 24 horas |
| `semanal` | 7 dias corridos |
| `mensal` | 30 dias corridos |
| `permanente` | Sem expiração automática |

O cálculo usa UTC e começa em `createdAt`, salvo quando `expiresAt` é informado explicitamente. O campo `startsAt` opcional impede o uso antes da data definida. A Key também pode ser revogada imediatamente com `revoked: true` ou `status: "revoked"`, desde que o cliente consiga consultar o GitHub novamente.

## Configuração do repositório

Crie um repositório público no GitHub e copie `keys.example.json` para `keys.json`. Depois, edite `key-system.js` e substitua:

```js
keysUrl: 'https://raw.githubusercontent.com/SEU_USUARIO/SEU_REPOSITORIO/main/keys.json'
```

pelo endereço RAW real, por exemplo:

```js
keysUrl: 'https://raw.githubusercontent.com/minha-conta/sv-keys/main/keys.json'
```

O arquivo `keys.json` pode usar este formato:

```json
{
  "version": 1,
  "keys": [
    {
      "id": "cliente-001",
      "hash": "HASH_SHA256_EM_HEXADECIMAL",
      "plan": "mensal",
      "createdAt": "2026-08-21T12:00:00Z",
      "revoked": false,
      "note": "Identificação administrativa opcional"
    }
  ]
}
```

## Criar uma Key

Gere uma Key longa e aleatória, sem reutilizá-la em outro serviço. Para calcular o hash SHA-256 no Linux ou macOS:

```bash
printf '%s' 'SV-2026-CLIENTE-UMA_KEY_LONGA_E_ALEATORIA' | sha256sum
```

No Windows PowerShell:

```powershell
$text = [Text.Encoding]::UTF8.GetBytes('SV-2026-CLIENTE-UMA_KEY_LONGA_E_ALEATORIA')
$hash = [Security.Cryptography.SHA256]::Create().ComputeHash($text)
([BitConverter]::ToString($hash) -replace '-', '').ToLower()
```

Cole somente o resultado hexadecimal no campo `hash`. Nunca publique o texto original da Key.

## Exemplos de validade

Para uma Key diária criada em 21/08/2026 às 12:00 UTC, use `plan: "diaria"` e `createdAt: "2026-08-21T12:00:00Z"`; ela expira em 22/08/2026 às 12:00 UTC. Para uma Key semanal, mensal ou permanente, mantenha o mesmo padrão e altere apenas `plan`.

Também é possível controlar a data final diretamente com `expiresAt`:

```json
{
  "id": "campanha-001",
  "hash": "...",
  "plan": "mensal",
  "createdAt": "2026-08-21T12:00:00Z",
  "expiresAt": "2026-09-15T23:59:59Z",
  "revoked": false
}
```

## Revogar ou estender

Para revogar, altere `revoked` para `true` e faça commit/push. Para estender uma licença, altere `expiresAt` ou o `createdAt` conforme a política administrativa. Como o navegador adiciona um parâmetro de cache-busting à consulta, alterações publicadas são buscadas em nova validação; ainda assim, a propagação do GitHub/CDN pode levar algum tempo.

## Limitações importantes

Este projeto é um site estático: a validação ocorre no navegador. Portanto, alguém com conhecimento técnico pode inspecionar ou modificar o JavaScript localmente. O uso de hashes protege o catálogo contra exposição direta das Keys, mas não transforma um cliente estático em um servidor antifraude. Para cobrança, controle de dispositivos, limite de uso, auditoria ou proteção contra alteração do relógio do dispositivo, a validação deve ser movida para uma API/backend sob seu controle.

O cliente não aceita uma Key vencida quando consegue consultar o catálogo. Sem conexão, ele usa apenas um cache curto de até 5 minutos; não existe modo offline prolongado.
