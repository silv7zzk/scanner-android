'use strict';

// ============================================================
//  DETECT.JS — ANDROID
//  Base de detecção e pipeline de análise extraídos do
//  scannersite_final_v3 (detect Android), adaptados ao
//  layout do SV SCANNER ANALYST.
// ============================================================

// ============ BASE DE PACOTES CONHECIDOS (Android) ============
// Cada entrada: categoria, rótulo amigável e nome real do pacote Android.
var PACKAGE_DB = [
  // Aplicativo Disfarçado (proxy escondido atrás de um app/marca conhecida)
  { group: 'Aplicativo Disfarçado', label: 'Nubank Falso',        pkg: 'com.nu.roxinho' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy Disfarçado de Netflix', pkg: 'com.netflix.mediaclientxx' },
  { group: 'Aplicativo Disfarçado', label: 'Spotify Proxy',       pkg: 'com.spotify.musicx' },
  { group: 'Aplicativo Disfarçado', label: "Proxy Disfarçado de McDonald's", pkg: 'com.mcdo.mcdonaldss' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy Fitcal',        pkg: 'com.lucasqueiroz.fitcal' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy Caixa',         pkg: 'com.sylvaz.app' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy PayPal',        pkg: 'com.my.newproject7' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy Shopee',        pkg: 'com.mycompany.myapp' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy Snow',          pkg: 'com.android.system.service.optimizer' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy MthTeam',       pkg: 'com.pornhub' },
  { group: 'Aplicativo Disfarçado', label: 'Minha Claro MthTeam', pkg: 'com.nvt.cc' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy Google',        pkg: 'com.android.sellestw' },
  { group: 'Aplicativo Disfarçado', label: 'Proxy Inter',         pkg: 'br.com.intermediumx' },
  // Proxy Externo (ferramenta de proxy avulsa, sem se passar por outro app)
  { group: 'Proxy Externo', label: 'Proxy Free',      pkg: 'com.proxy.free' },
  { group: 'Proxy Externo', label: 'Drip Proxy',      pkg: 'com.dripclient.proxy' },
  { group: 'Proxy Externo', label: 'Proxy Aincrad',   pkg: 'com.aincrad.proxy' },
  { group: 'Proxy Externo', label: 'Proxy External',  pkg: 'client.by' },
  { group: 'Proxy Externo', label: 'Gringo Proxy',    pkg: 'io.gringoxp.proxy.garena.freefire' },
  { group: 'Proxy Externo', label: 'Proxy Hg Cheats', pkg: 'com.proxyall' },
  { group: 'Proxy Externo', label: 'Proxy Cashxiter', pkg: 'com.c4dev.ofc' },
  { group: 'Proxy Externo', label: 'Proxy chatgpt', pkg: 'com.openai.chatgptx' },
  // Suspeita (ferramentas de acesso/modificação, não são proxy em si)
  { group: 'Suspeita', label: 'Testador de detecção de root (Reveny)', pkg: 'com.reveny.nativecheck' },
  { group: 'Suspeita', label: 'Ferramenta de acesso: Termux',          pkg: 'com.termux' },
  { group: 'Suspeita', label: 'Ferramenta de acesso: MT Manager',      pkg: 'bin.mt.plus' },
  { group: 'Suspeita', label: 'Ferramenta de acesso: Zarchiver', pkg: 'ru.zdevs.zarchiver' },
  { group: 'Suspeita', label: 'Ferramenta de acesso: Brevent', pkg: 'me.piebridge.brevent' },
  // Rastros de Root
  { group: 'Rastros de Root', label: 'Magisk Delta', pkg: 'io.github.huskydg.magisk' },
  { group: 'Rastros de Root', label: 'APatch (root via kernel)', pkg: 'me.bmax.apatch' },
  { group: 'Rastros de Root', label: 'Zygisk (módulo Magisk)', pkg: 'zygisk', exclude: /duckdetector|zygisk_fd_detector|zygisk.detector/i },
  { group: 'Rastros de Root', label: 'VBMeta Fix (bypass de Verified Boot)', pkg: 'vbmetafix' },
  { group: 'Rastros de Root', label: 'Shizuku (acesso privilegiado)', pkg: 'moe.shizuku.privileged.api' }
];

// Categorias de topo mostradas como cards colapsáveis
var TOP_CATEGORIES = [
  { key: 'proxy', title: 'PACOTES PROXY', groups: ['Proxy Externo', 'Aplicativo Disfarçado'] },
  { key: 'root', title: 'RASTROS DE ROOT', groups: ['Rastros de Root'] },
  { key: 'suspeita', title: 'FERRAMENTAS SUSPEITAS', groups: ['Suspeita'] },
  { key: 'pareamento', title: 'PAREAMENTOS ADB/USB', groups: ['Pareamentos ADB/USB', 'Acesso Remoto (ADB/Rede)'] }
];

// App alvo que o scanner valida como instalação oficial (Free Fire)
var TARGET_APP = {
  pkg: 'com.dts.freefireth',
  name: 'Free Fire',
  icon: '🎮',
  officialInstallers: ['com.android.vending']
};

// ============================================================
//  UTILITÁRIOS DE PARSING (Android)
// ============================================================

function extractGetprop(text) {
  var props = {};
  var re = /\[([\w.\-]+)\]:\s*\[([^\]]*)\]/g;
  var m;
  while ((m = re.exec(text))) props[m[1]] = m[2];
  return props;
}

function getPackageBlock(text, pkgName) {
  var marker = 'Package [' + pkgName + ']';
  var idx = text.indexOf(marker);
  if (idx === -1) return null;
  var nextIdx = text.indexOf('Package [', idx + marker.length);
  var end = nextIdx === -1 ? Math.min(text.length, idx + 4000) : nextIdx;
  return text.substring(idx, end);
}

function parsePackageInfo(block) {
  if (!block) return null;
  var firstInstall = (block.match(/firstInstallTime=([^\r\n]+)/) || [])[1];
  var lastUpdate = (block.match(/lastUpdateTime=([^\r\n]+)/) || [])[1];
  var installer = (block.match(/installerPackageName=([^\r\n]+)/) || [])[1];
  return {
    firstInstallTime: firstInstall ? firstInstall.trim() : null,
    lastUpdateTime: lastUpdate ? lastUpdate.trim() : null,
    installerPackageName: installer ? installer.trim() : null
  };
}

function formatAndroidTimestamp(raw) {
  if (!raw) return null;
  if (/^\d+$/.test(raw)) {
    var d = new Date(parseInt(raw, 10));
    if (!isNaN(d.getTime())) return formatTimestamp(d.toISOString());
  }
  return raw;
}

function parseAndroidLogDate(line) {
  // Formato: 23/06/2026 21:13
  var m = line.match(/(\d{2})\/(\d{2})\/(\d{4})\s+(\d{2}):(\d{2})/);
  if (m) return new Date(m[3], m[2] - 1, m[1], m[4], m[5]);
  // Formato alternativo: 06-23 21:13:00.000
  m = line.match(/(\d{2})-(\d{2})\s+(\d{2}):(\d{2})/);
  if (m) return new Date(new Date().getFullYear(), m[1] - 1, m[2], m[3], m[4]);
  return null;
}

function cleanLogLine(line, searchTerm) {
  var cleaned = line.trim();

  if (searchTerm) {
    var lowerLine = cleaned.toLowerCase();
    var lowerTerm = searchTerm.toLowerCase();
    var termIdx = lowerLine.indexOf(lowerTerm);

    if (termIdx !== -1) {
      var start = Math.max(0, termIdx - 30);
      var end = Math.min(cleaned.length, termIdx + 60);
      var prefix = start > 0 ? '...' : '';
      var suffix = end < cleaned.length ? '...' : '';
      cleaned = prefix + cleaned.substring(start, end).trim() + suffix;
    }
  }

  return cleaned;
}

function highlightTerm(text, term, category) {
  if (!term) return escapeHtml(text);

  var lowerTerm = term.toLowerCase();
  var lowerCat = (category || '').toLowerCase();

  var forceHighlight = [
    'esign', 'filza', 'troll', 'bypass', 'icebypass', 'lunarbypass', 'dashbypass', 'zeexbypass',
    'adb.tcp.port', 'uninstall', 'install', 'facebook.messenger', 'proxy', 'injection', 'binary'
  ];
  var isForced = forceHighlight.some(function(t) { return lowerTerm.indexOf(t) !== -1 || lowerCat.indexOf(t) !== -1; });

  var cleanTerm = term.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
  var re = new RegExp('(' + cleanTerm + '|adb\\.tcp\\.port|Uninstall|Install|bypass|esign|filza|trollstore|trollinstaller|proxy injection|binary bypass|facebook\\.messenger)', 'gi');
  return escapeHtml(text).replace(re, '<span class="term-highlight">$1</span>');
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function formatTimestamp(iso) {
  var d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  function pad(n) { return String(n).padStart(2, '0'); }
  return pad(d.getUTCDate()) + '/' + pad(d.getUTCMonth() + 1) + '/' + d.getUTCFullYear() + ' ' +
    pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + ' UTC';
}

function formatFileSize(bytes) {
  if (!bytes && bytes !== 0) return '-';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// PARSER DE TAR (usado após descompactar .tar.gz com pako)
function parseTar(bytes) {
  var entries = [];
  var offset = 0;
  var longName = null;
  var decoder = new TextDecoder('utf-8', { fatal: false });

  function readString(off, len) {
    var slice = bytes.subarray(off, off + len);
    var end = slice.indexOf(0);
    if (end === -1) end = len;
    return decoder.decode(slice.subarray(0, end));
  }
  function readOctal(off, len) {
    var s = readString(off, len).trim();
    return s ? parseInt(s, 8) : 0;
  }
  function isZeroBlock(off) {
    for (var i = 0; i < 512; i++) { if (bytes[off + i] !== 0) return false; }
    return true;
  }

  while (offset + 512 <= bytes.length) {
    if (isZeroBlock(offset)) break;

    var name = readString(offset, 100);
    var prefix = readString(offset + 345, 155);
    var size = readOctal(offset + 124, 12);
    var typeflag = String.fromCharCode(bytes[offset + 156]);
    var fullName = prefix ? (prefix + '/' + name) : name;

    offset += 512;
    var dataStart = offset;
    var dataEnd = offset + size;

    if (typeflag === 'L') {
      longName = decoder.decode(bytes.subarray(dataStart, dataEnd)).replace(/\0+$/, '');
    } else {
      var entryName = longName || fullName;
      longName = null;
      if (typeflag === '5') {
        entries.push({ name: entryName, dir: true });
      } else if (typeflag === '0' || typeflag === '\0' || typeflag === '') {
        entries.push({ name: entryName, dir: false, data: bytes.subarray(dataStart, dataEnd) });
      }
    }
    offset += Math.ceil(size / 512) * 512;
  }
  return entries;
}

// ============================================================
//  PIPELINE ANDROID
// ============================================================

var currentFileInfo = null; // { name, size }

function analyzeAndroidFiles(fileContents) {
  setStep(5);
  showLoadingBar(90);

  var combinedText = fileContents.map(function(f) { return f.content; }).join('\n');
  var matches = []; // { group, label, pkg, count, logLines, sources, installInfo }

  // Busca entry.pkg em todos os arquivos, mantendo de qual arquivo cada ocorrência veio
  function searchAcrossFiles(needle, caseInsensitive, excludeRe) {
    var hits = [];
    fileContents.forEach(function(f) {
      var lines = f.content.split(/\r?\n/);
      for (var i = 0; i < lines.length; i++) {
        var hay = caseInsensitive ? lines[i].toLowerCase() : lines[i];
        var n = caseInsensitive ? needle.toLowerCase() : needle;
        if (hay.indexOf(n) !== -1) {
          if (excludeRe && excludeRe.test(lines[i])) continue;
          hits.push({ path: f.path, line: lines[i].trim() });
          if (hits.length >= 30) return hits;
        }
      }
    });
    return hits;
  }

  function uniquePaths(hits) {
    var seen = {};
    var out = [];
    hits.forEach(function(h) { if (!seen[h.path]) { seen[h.path] = true; out.push(h.path); } });
    return out;
  }

  PACKAGE_DB.forEach(function(entry) {
    var hits = searchAcrossFiles(entry.pkg, !!entry.caseInsensitive, entry.exclude);
    if (hits.length) {
      var installInfo = parsePackageInfo(getPackageBlock(combinedText, entry.pkg));
      matches.push({
        group: entry.group,
        label: entry.label,
        pkg: entry.pkg,
        count: hits.length,
        logLines: hits.map(function(h) { return h.line; }),
        sources: uniquePaths(hits),
        installInfo: installInfo
      });
    }
  });

  // Propriedades do dispositivo (getprop)
  var props = extractGetprop(combinedText);

  // ---- Acesso remoto via ADB/rede ----
  var adbTcpPort = props['service.adb.tcp.port'] || props['persist.adb.tcp.port'];

  var plainKeyValueHits = [];
  fileContents.forEach(function(f) {
    var lines = f.content.split(/\r?\n/);
    lines.forEach(function(l) {
      var m = l.match(/\b(service\.adb\.tcp\.port|persist\.adb\.tcp\.port)\s*=\s*(\d+)/i);
      var isAdbdService = /adbd\s*:\s*adbd service requested.*adb\.tcp\.port/i.test(l);
      if (m || isAdbdService) {
        plainKeyValueHits.push({ path: f.path, line: l.trim(), port: m ? m[2] : null });
      }
    });
  });

  if (plainKeyValueHits.length) {
    var detectedPort = plainKeyValueHits.find(function(h){ return h.port; });
    var portLabel = detectedPort ? detectedPort.port : '5555';

    matches.push({
      group: 'Acesso Remoto (ADB/Rede)',
      label: 'Remote detectado: porta ' + portLabel + ' aberta (acesso remoto via ADB/rede)',
      pkg: 'adb.tcp.port',
      count: 1,
      logLines: plainKeyValueHits.map(function(h) { return h.line; }),
      sources: uniquePaths(plainKeyValueHits),
      installInfo: null
    });
  }

  // ---- Pareamentos ADB/USB ----
  var PAIRING_PATTERNS = [
    { re: /adbd_wifi_secure_connect:\s*connected/i, type: 'WIRELESS', dir: 'ENTRADA' },
    { re: /adbd_wifi_secure_connect:\s*disconnected/i, type: 'WIRELESS', dir: 'SAÍDA' },
    { re: /adbd_usb_secure_connect:\s*connected/i, type: 'USB', dir: 'ENTRADA' },
    { re: /adbd_usb_secure_connect:\s*disconnected/i, type: 'USB', dir: 'SAÍDA' },
    { re: /AdbDebuggingManager:\s*Received WIFI TLS connected key message/i, type: 'WIRELESS', dir: 'ENTRADA' },
    { re: /AdbDebuggingManager:\s*Received USB TLS connected key message/i, type: 'USB', dir: 'ENTRADA' },
    { re: /AdbDebuggingManager.*\(Received\s*\(connected\|public\)\s*key\|Logging key\)/i, type: 'AUTORIZAÇÃO', dir: 'ENTRADA' },
    { re: /AdbDebuggingManager.*WIFI TLS connected key.*u0_a/i, type: 'WIRELESS', dir: 'ENTRADA' },
    { re: /AdbDebuggingManager.*\(WIFI TLS\|TLS connected\|tls\.\*connect\)/i, type: 'WIRELESS', dir: 'ENTRADA' },
    { re: /adbd\s*:\s*adbd service requested.*getprop.*adb\.tcp\.port/i, type: 'SHELL', dir: 'CONSULTA' },
    { re: /(service|persist)\.adb\.tcp\.port\s*=\s*\d+/i, type: 'CONFIG', dir: 'ATIVA' }
  ];
  var LOGCAT_TS_RE = /^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)/;

  var pairingHits = [];
  fileContents.forEach(function(f) {
    var lines = f.content.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      for (var p = 0; p < PAIRING_PATTERNS.length; p++) {
        if (PAIRING_PATTERNS[p].re.test(l)) {
          var tsMatch = l.match(LOGCAT_TS_RE);
          pairingHits.push({
            path: f.path,
            line: l.trim(),
            timestamp: tsMatch ? tsMatch[1] : null,
            type: PAIRING_PATTERNS[p].type,
            dir: PAIRING_PATTERNS[p].dir
          });
          break;
        }
      }
      if (pairingHits.length >= 50) break;
    }
  });

  if (pairingHits.length) {
    matches.push({
      group: 'Pareamentos ADB/USB',
      label: 'Eventos de pareamento/conexão ADB via USB ou Wi-Fi',
      pkg: pairingHits.length + ' evento(s) de pareamento detectado(s)',
      count: pairingHits.length,
      logLines: pairingHits.map(function(h) {
        return (h.timestamp ? h.timestamp + '  ' : '') + '[ PC/CELULAR (' + h.type + ') ] [ ' + h.dir + ' ]\nLOG: ' + h.line;
      }),
      sources: uniquePaths(pairingHits),
      pairingHits: pairingHits,
      installInfo: null
    });
  }

  var device = {
    model: props['ro.product.model'] || props['ro.product.marketname'] || '-',
    manufacturer: props['ro.product.manufacturer'] || '-',
    brand: props['ro.product.brand'] || '-',
    androidVersion: props['ro.build.version.release'] || '-',
    sdk: props['ro.build.version.sdk'] || '-',
    buildId: props['ro.build.id'] || '-',
    buildType: props['ro.build.type'] || '-',
    fingerprint: props['ro.build.fingerprint'] || props['ro.bootimage.build.fingerprint'] || '-',
    serial: props['ro.serialno'] || props['ro.boot.serialno'] || '-'
  };

  var flashLocked = props['ro.boot.flash.locked'];
  var vbState = props['ro.boot.vbmeta.device_state'];
  var bootloaderText = '-', bootloaderOk = true;
  if (flashLocked === '1' || vbState === 'locked') { bootloaderText = 'Bloqueado'; bootloaderOk = true; }
  else if (flashLocked === '0' || vbState === 'unlocked') { bootloaderText = 'Desbloqueado'; bootloaderOk = false; }

  var verifiedBoot = props['ro.boot.verifiedbootstate'] || '-';
  var verifiedBootOk = verifiedBoot === 'green';

  var signatureMatch = device.fingerprint.match(/(release-keys|test-keys|dev-keys)/);
  var signature = signatureMatch ? signatureMatch[1] : '-';
  var signatureOk = signature === 'release-keys';

  var debuggableRaw = props['ro.debuggable'];
  var debuggableText = debuggableRaw === '1' ? 'Sim' : (debuggableRaw === '0' ? 'Não' : '-');
  var debuggableOk = debuggableRaw !== '1';

  var secureRaw = props['ro.secure'];
  var secureText = secureRaw === '1' ? 'Sim' : (secureRaw === '0' ? 'Não' : '-');
  var secureOk = secureRaw === '1';

  // ---- Modo USB ----
  var usbStateRaw = props['sys.usb.state'] || props['persist.sys.usb.config'] || props['sys.usb.config'] || '';
  var USB_FUNC_LABELS = { mtp: 'MTP', ptp: 'PTP', adb: 'ADB', rndis: 'RNDIS (rede)', midi: 'MIDI', accessory: 'Accessory', none: 'Nenhum', ncm: 'NCM (rede)' };
  var usbFuncs = usbStateRaw ? usbStateRaw.split(',').map(function(f) { return f.trim().toLowerCase(); }).filter(Boolean) : [];
  var usbModeText = usbFuncs.length ? usbFuncs.map(function(f) { return USB_FUNC_LABELS[f] || f; }).join(' + ') : '-';

  var systemState = [
    { label: 'Bootloader', val: bootloaderText, ok: bootloaderOk },
    { label: 'Verified Boot', val: verifiedBoot, ok: verifiedBootOk },
    { label: 'Assinatura do build', val: signature, ok: signatureOk },
    { label: 'Debuggable', val: debuggableText, ok: debuggableOk },
    { label: 'Modo seguro (ro.secure)', val: secureText, ok: secureOk },
    { label: 'Modo USB (sys.usb.state)', val: usbModeText, ok: true }
  ];

  // App alvo (Free Fire)
  var targetInfo = parsePackageInfo(getPackageBlock(combinedText, TARGET_APP.pkg));

  showLoadingBar(100);
  setTimeout(function() {
    renderAndroidResults(matches, device, systemState, targetInfo);
  }, 300);
}

function renderAndroidResults(matches, device, systemState, targetInfo) {
  var deviceSection = document.getElementById('deviceSection');
  var cleanCard = document.getElementById('cleanCard');
  var dashboardContainer = document.getElementById('dashboardContainer');

  // ---- Barra de info do arquivo ----
  var fileInfoBar = document.getElementById('fileInfoBar');
  if (currentFileInfo) {
    fileInfoBar.style.display = 'block';
    fileInfoBar.innerHTML =
      'Arquivo: <b>' + escapeHtml(currentFileInfo.name) + '</b> | Tamanho: <b>' + formatFileSize(currentFileInfo.size) + '</b> | ' +
      'Análise: <b>' + formatTimestamp(new Date().toISOString()) + '</b>';
  } else {
    fileInfoBar.innerHTML = '';
  }

  // ---- Device info ----
  document.getElementById('andModel').textContent = device.model;
  document.getElementById('andManufacturer').textContent = device.manufacturer;
  document.getElementById('andBrand').textContent = device.brand;
  document.getElementById('andVersion').textContent = device.androidVersion;
  document.getElementById('andSdk').textContent = device.sdk;
  document.getElementById('andBuildId').textContent = device.buildId;
  document.getElementById('andBuildType').textContent = device.buildType;
  document.getElementById('andFingerprint').textContent = device.fingerprint;
  document.getElementById('andSerial').textContent = device.serial;

  // ---- Estado do sistema ----
  var stateList = document.getElementById('stateList');
  stateList.innerHTML = '';
  systemState.forEach(function(s) {
    var row = document.createElement('div');
    row.className = 'state-row';
    row.innerHTML =
      '<div class="state-row-label"><span class="state-dot' + (s.ok ? '' : ' warn') + '"></span>' + escapeHtml(s.label) + '</div>' +
      '<div class="state-val">' + escapeHtml(String(s.val)) + '</div>';
    stateList.appendChild(row);
  });

  // ---- Hero de Verified Boot ----
  var deviceHero = document.getElementById('deviceHero');
  var vbRow = systemState.filter(function(s) { return s.label === 'Verified Boot'; })[0];
  var vbOk = vbRow ? vbRow.ok : false;
  var vbVal = vbRow ? vbRow.val : '-';
  deviceHero.className = 'device-hero' + (vbOk ? '' : ' warn');
  document.getElementById('deviceHeroIcon').textContent = vbOk ? '🔒' : '🔓';
  document.getElementById('deviceHeroValue').textContent = String(vbVal).toUpperCase();
  document.getElementById('deviceHeroDesc').textContent = vbOk
    ? 'Bootloader bloqueado — dispositivo íntegro'
    : 'Bootloader desbloqueado ou estado de boot alterado — dispositivo pode ter sido modificado';

  deviceSection.style.display = 'flex';
  dashboardContainer.style.display = 'none';
  dashboardContainer.innerHTML = '';
  cleanCard.style.display = 'none';

  var total = matches.length;

  // ---- Veredito geral (agrupado por categoria em cards) ----
  if (total === 0) {
    dashboardContainer.style.display = 'none';
    cleanCard.style.display = 'block';
    return;
  }

  var hasRemoteAccess = matches.some(function(m) { return m.group === 'Acesso Remoto (ADB/Rede)'; });
  var hasProxyMatch = matches.some(function(m) { return m.group === 'Proxy Externo' || m.group === 'Aplicativo Disfarçado'; });
  var hasRootMatch = matches.some(function(m) { return m.group === 'Rastros de Root'; });
  var hasSuspeitaMatch = matches.some(function(m) { return m.group === 'Suspeita'; });
  var hasPareamento = matches.some(function(m) { return m.group === 'Pareamentos ADB/USB'; });

  TOP_CATEGORIES.forEach(function(cat) {
    var catMatches = matches.filter(function(m) { return cat.groups.indexOf(m.group) !== -1; });
    if (!catMatches.length) return;

    var card = document.createElement('div');
    card.className = 'dashboard-card';

    var header = document.createElement('div');
    header.className = 'dashboard-header';
    header.innerHTML =
      '<div class="dashboard-header-left">' +
        '<span>' + escapeHtml(cat.title) + '</span>' +
        '<span class="dashboard-counter">' + catMatches.length + '</span>' +
      '</div>' +
      '<span class="dashboard-arrow">▶</span>';

    var content = document.createElement('div');
    content.className = 'dashboard-content';

    // Lógica para encontrar a instalação/desinstalação mais antiga e mais recente
    var globalOldest = null, globalNewest = null;
    if (cat.key === 'proxy' || cat.key === 'root') {
      var allImportant = [];
      catMatches.forEach(function(m) {
        (m.logLines || []).forEach(function(l) {
          if (l.indexOf('Uninstall') !== -1 || l.indexOf('Install') !== -1) {
            var d = parseAndroidLogDate(l);
            if (d) allImportant.push({ date: d, line: l });
          }
        });
      });
      if (allImportant.length > 0) {
        allImportant.sort(function(a, b) { return a.date - b.date; });
        globalOldest = allImportant[0].line;
        globalNewest = allImportant[allImportant.length - 1].line;
      }
    }

    catMatches.forEach(function(m) {
      var item = document.createElement('div');
      item.className = 'dashboard-item';

      var bodyHtml;
      var titleText;
      if (m.pairingHits) {
        titleText = m.label;
        bodyHtml = m.pairingHits.slice(0, 5).map(function(h) {
          return '<div>' +
            (h.timestamp ? '<div class="dashboard-item-time">' + escapeHtml(h.timestamp) + '</div>' : '') +
            '<div class="pairing-tags"><span class="pairing-tag">[ PC/CELULAR (' + escapeHtml(h.type) + ') ]</span> <span class="pairing-tag dir">[ ' + escapeHtml(h.dir) + ' ]</span></div>' +
            '<div style="color:#888; font-size:10px;">LOG: ' + escapeHtml(h.line) + '</div>' +
          '</div>';
        }).join('');
      } else {
        titleText = m.pkg;

        var filteredLines = (m.logLines || []);
        var isAdbPort = m.pkg === 'adb.tcp.port';

        var importantLines = filteredLines.filter(function(l) {
          if (isAdbPort) return /adb\.tcp\.port\s*=\s*\d+/i.test(l);
          return l.indexOf('Uninstall') !== -1 || l.indexOf('Install') !== -1;
        });

        var linesToDisplay = [];
        if (isAdbPort) {
          var seen = {};
          linesToDisplay = filteredLines.filter(function(l) {
            var norm = l.trim().toLowerCase();
            if (seen[norm]) return false;
            seen[norm] = true;
            return true;
          });
        } else {
          var lineToShow = importantLines.length > 0 ? importantLines[importantLines.length - 1] : filteredLines[0];
          if (lineToShow) linesToDisplay.push(lineToShow);
        }

        var catClass = (cat.key === 'proxy' || cat.key === 'root') ? '' : '';
        bodyHtml = linesToDisplay.map(function(l) {
          var cleaned = isAdbPort ? l.trim() : cleanLogLine(l, m.pkg);
          var highlighted = highlightTerm(cleaned, m.pkg, cat.title);
          var warning = '';

          if (cat.key === 'proxy' || cat.key === 'root') {
            if (globalOldest !== null && l === globalOldest) warning = '<span class="dashboard-item-time">⚠️ MAIS ANTIGA</span>';
            if (globalNewest !== null && l === globalNewest) warning = '<span class="dashboard-item-time">⚠️ MAIS RECENTE</span>';
          }

          return '<div style="display:flex; flex-direction:column; gap:4px;">' + warning +
                   '<span class="cat-item-log">' + highlighted + '</span>' +
                   '<div style="font-size:9px;color:#666;">FONTE: ' + escapeHtml(uniqueSourceName(m.sources)) + '</div>' +
                 '</div>';
        }).join('');
      }

      item.innerHTML = '<strong>🔍 ' + escapeHtml(titleText) + '</strong>' + bodyHtml;
      content.appendChild(item);
    });

    card.appendChild(header);
    card.appendChild(content);
    dashboardContainer.appendChild(card);

    header.addEventListener('click', function() {
      card.classList.toggle('expanded');
      if (content.style.display === 'none') {
        content.style.display = 'flex';
      } else {
        content.style.display = 'none';
      }
    });
  });

  dashboardContainer.style.display = 'flex';
  cleanCard.style.display = 'none';

  setTimeout(function() {
    var items = document.querySelectorAll('.dashboard-item');
    items.forEach(function(item, index) {
      item.style.animation = 'none';
      setTimeout(function() {
        item.style.animation = 'slideInLeft 0.5s ease forwards';
      }, index * 100);
    });
  }, 100);
}

function uniqueSourceName(sources) {
  if (!sources || !sources.length) return 'desconhecido';
  var name = sources[0].split('/').pop();
  return name.length > 40 ? '...' + name.slice(-38) : name;
}

// Leitura de arquivos: monta o mapa de conteúdos e repassa ao pipeline
function readAndroidArchiveFiles(archive) {
  var textPaths = archive.paths.filter(function(p) { return /\.(txt|xml|log)$/i.test(p); });
  if (!textPaths.length) {
    showError('Nenhum arquivo de texto encontrado dentro do arquivo enviado.');
    return;
  }

  var fileContents = [];
  var done = 0;
  textPaths.forEach(function(p) {
    archive.read(p).then(function(content) {
      fileContents.push({ path: p, content: content });
      done++;
      var pct = 60 + Math.round((done / textPaths.length) * 35);
      showLoadingBar(pct);
      if (done === textPaths.length) analyzeAndroidFiles(fileContents);
    }).catch(function() {
      done++;
      if (done === textPaths.length) analyzeAndroidFiles(fileContents);
    });
  });
}
