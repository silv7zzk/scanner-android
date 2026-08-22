/*
 * Sistema de Keys via GitHub para o SV Scanner Analyst.
 *
 * IMPORTANTE: altere keysUrl para o endereço RAW do seu arquivo keys.json.
 * Nunca coloque tokens pessoais do GitHub neste arquivo ou no keys.json.
 */
window.KEY_SYSTEM_CONFIG = window.KEY_SYSTEM_CONFIG || {
    keysUrl: 'https://raw.githubusercontent.com/silv7zzk/sv-keys/main/keys.json',
    requestTimeoutMs: 8000,
    cacheTtlMs: 5 * 60 * 1000
};

const KEY_PLANS = Object.freeze({
    diaria: { label: 'Diária', durationMs: 1 * 24 * 60 * 60 * 1000 },
    semanal: { label: 'Semanal', durationMs: 7 * 24 * 60 * 60 * 1000 },
    mensal: { label: 'Mensal', durationMs: 30 * 24 * 60 * 60 * 1000 },
    permanente: { label: 'Permanente', durationMs: null }
});

const KEY_CACHE_KEY = 'sv_scanner_key_cache_v2';
let keyCatalogPromise = null;

function normalizeKey(value) {
    return String(value || '')
        .normalize('NFKC')
        .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200D\uFEFF]/g, '')
        .replace(/\s+/g, '')
        .toUpperCase();
}

async function sha256(value) {
    const bytes = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function parseDate(value, fieldName) {
    if (!value) return null;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) throw new Error(`Data inválida em ${fieldName}.`);
    return date;
}

function getExpiry(record, plan) {
    const explicitExpiry = parseDate(record.expiresAt, 'expiresAt');
    if (explicitExpiry) return explicitExpiry;
    if (plan.durationMs === null) return null;
    const createdAt = parseDate(record.createdAt, 'createdAt');
    if (!createdAt) throw new Error('Key sem createdAt.');
    return new Date(createdAt.getTime() + plan.durationMs);
}

function validateCatalogShape(payload) {
    const records = Array.isArray(payload) ? payload : payload && payload.keys;
    if (!Array.isArray(records)) throw new Error('O catálogo precisa conter um array "keys".');
    return records;
}

async function fetchKeyCatalog() {
    const url = window.KEY_SYSTEM_CONFIG.keysUrl;
    if (!url || url.includes('SEU_USUARIO') || url.includes('SEU_REPOSITORIO')) {
        throw new Error('Configure o endereço RAW do keys.json em key-system.js.');
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), window.KEY_SYSTEM_CONFIG.requestTimeoutMs);
    try {
        const separator = url.includes('?') ? '&' : '?';
        const response = await fetch(`${url}${separator}cacheBust=${Date.now()}`, {
            method: 'GET', cache: 'no-store', signal: controller.signal,
            headers: { Accept: 'application/json' }
        });
        if (!response.ok) throw new Error(`GitHub respondeu HTTP ${response.status}.`);
        return validateCatalogShape(await response.json());
    } finally {
        clearTimeout(timeout);
    }
}

async function getKeyCatalog() {
    if (!keyCatalogPromise) {
        keyCatalogPromise = fetchKeyCatalog().catch(error => {
            keyCatalogPromise = null;
            throw error;
        });
    }
    return keyCatalogPromise;
}

function cacheCatalog(records) {
    try {
        localStorage.setItem(KEY_CACHE_KEY, JSON.stringify({ savedAt: Date.now(), records }));
    } catch (_) { /* armazenamento local pode estar bloqueado */ }
}

function readCachedCatalog() {
    try {
        const cached = JSON.parse(localStorage.getItem(KEY_CACHE_KEY) || 'null');
        if (cached && Date.now() - cached.savedAt <= window.KEY_SYSTEM_CONFIG.cacheTtlMs) return cached.records;
    } catch (_) { /* cache inválido é descartado */ }
    return null;
}

function formatDate(date) {
    return date ? date.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : 'sem expiração';
}

async function validateAccessKey(input) {
    const normalized = normalizeKey(input);
    if (!normalized) return { ok: false, message: 'Digite uma Key.' };

    let records;
    try {
        records = await getKeyCatalog();
        cacheCatalog(records);
    } catch (networkError) {
        return { ok: false, message: networkError.name === 'AbortError' ? 'Tempo esgotado ao consultar o GitHub. A Key não pode ser validada sem conexão.' : networkError.message };
    }

    const hash = await sha256(normalized);
    const record = records.find(item => item && String(item.hash || '').toLowerCase() === hash);
    if (!record) return { ok: false, message: 'Key inválida.' };
    if (record.finalizedAt || record.status === 'finalizada') return { ok: false, message: 'Esta Key foi finalizada.' };
    if (record.revoked === true || record.status === 'revoked' || record.status === 'bloqueada') return { ok: false, message: 'Esta Key foi bloqueada.' };

    const planKey = String(record.plan || '').toLowerCase();
    const plan = KEY_PLANS[planKey];
    if (!plan) return { ok: false, message: 'Plano de Key não reconhecido.' };

    const now = new Date();
    const startsAt = parseDate(record.startsAt || record.createdAt, 'startsAt');
    if (startsAt && now < startsAt) return { ok: false, message: `Key ainda não ativada. Início: ${formatDate(startsAt)}.` };

    let expiresAt;
    try { expiresAt = getExpiry(record, plan); }
    catch (error) { return { ok: false, message: error.message }; }
    if (expiresAt && now >= expiresAt) return { ok: false, message: `Key expirada em ${formatDate(expiresAt)}.` };

    return {
        ok: true,
        record,
        plan: planKey,
        planLabel: plan.label,
        expiresAt,
        expiresLabel: formatDate(expiresAt),
        keyId: record.id || hash.slice(0, 12)
    };
}

window.KeySystem = { validateAccessKey, KEY_PLANS };
