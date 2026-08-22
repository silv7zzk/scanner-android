// ============================================================
//  SCRIPT.JS — ANDROID (SV SCANNER ANALYST)
//  UI e lógica do scanner do Silva:
//  - Efeito Matrix (canvas de fundo)
//  - Tela de login com Keys gerenciadas via GitHub (diária, semanal, mensal e permanente)
//  - Overlays ACCESS GRANTED / ACCESS DENIED
//  - Upload (clique, arrastar e soltar) .zip / .tar.gz / .txt
//  - Etapas de progresso
// ============================================================

// ============ EFEITO MATRIX ============
const canvas = document.getElementById('matrixCanvas');
const ctx = canvas.getContext('2d');
let width, height, columns, fontSize = 15, drops;

function resizeCanvas() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    columns = Math.floor(width / fontSize);
    drops = new Array(columns).fill(1);
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

function drawMatrix() {
    ctx.fillStyle = 'rgba(0, 0, 0, 0.05)'; ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = '#111'; ctx.font = fontSize + 'px monospace';
    for (let i = 0; i < drops.length; i++) {
        const text = Math.random() > 0.5 ? '0' : '1';
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
    }
}
setInterval(drawMatrix, 50);

// ============ LOGIN / KEYS VIA GITHUB ============
let authorizedKey = null;

function setLoginMessage(message, isError = true) {
    const error = document.getElementById('loginError');
    const status = document.getElementById('keyStatus');
    if (isError) {
        error.textContent = message;
        error.style.display = 'block';
        status.textContent = '';
    } else {
        error.style.display = 'none';
        status.textContent = message;
    }
}

async function handleLogin() {
    const field = document.getElementById('passwordField');
    const button = document.getElementById('loginBtn');
    const pass = field.value;
    button.disabled = true;
    button.textContent = 'CONSULTANDO...';
    setLoginMessage('Consultando catálogo seguro no GitHub...', false);

    try {
        const result = await window.KeySystem.validateAccessKey(pass);
        if (!result.ok) {
            document.getElementById('accessDeniedOverlay').style.display = 'flex';
            setTimeout(() => {
                document.getElementById('accessDeniedOverlay').style.display = 'none';
                setLoginMessage(result.message, true);
            }, 900);
            return;
        }

        authorizedKey = result;
        document.getElementById('accessGrantedOverlay').style.display = 'flex';
        setTimeout(() => {
            document.getElementById('accessGrantedOverlay').style.display = 'none';
            document.getElementById('loginOverlay').style.display = 'none';
            document.getElementById('mainContainer').style.display = 'flex';
            const plan = result.expiresAt ? `${result.planLabel} | expira: ${result.expiresLabel}` : `${result.planLabel} | sem expiração`;
            document.getElementById('keyStatus').textContent = `Acesso autorizado: ${plan}`;
        }, 1200);
    } catch (error) {
        setLoginMessage(`Falha na validação: ${error.message}`, true);
    } finally {
        button.disabled = false;
        button.textContent = 'AUTORIZAR';
    }
}
document.getElementById('loginBtn').addEventListener('click', handleLogin);

// ============ UPLOAD: CLIQUE ============
const uploadOuter = document.getElementById('uploadOuter');
const fileInput = document.getElementById('fileInput');

uploadOuter.addEventListener('click', (e) => {
    if (e.target === fileInput) return;
    fileInput.click();
});

// ============ UPLOAD: DRAG & DROP ============
['dragenter', 'dragover'].forEach(evt => {
    uploadOuter.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        uploadOuter.style.borderColor = 'rgba(255,255,255,0.5)';
        uploadOuter.style.background = 'rgba(40,40,40,0.9)';
    });
});
['dragleave', 'dragend'].forEach(evt => {
    uploadOuter.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        uploadOuter.style.borderColor = '';
        uploadOuter.style.background = '';
    });
});
uploadOuter.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadOuter.style.borderColor = '';
    uploadOuter.style.background = '';
    const files = e.dataTransfer.files;
    if (files && files.length) startScan(files[0]);
});
document.addEventListener('dragover', (e) => { e.preventDefault(); });
document.addEventListener('drop', (e) => {
    if (e.target !== uploadOuter && !uploadOuter.contains(e.target)) e.preventDefault();
});

fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files.length) startScan(fileInput.files[0]);
});

// ============ ETAPAS DE PROGRESSO ============
function updateStep(num, status) {
    const step = document.getElementById('step' + num);
    if (status === 'active') { step.classList.add('active'); step.classList.remove('completed'); }
    else if (status === 'completed') { step.classList.add('completed'); step.classList.remove('active'); }
}

function showLoadingBar(pct) {
    const bar = document.getElementById('loadingBar');
    if (bar) bar.style.width = pct + '%';
}

function setStep(n) { updateStep(n, 'active'); }

function resetUI() {
    document.getElementById('errorCard').style.display = 'none';
    document.getElementById('progressContainer').style.display = 'none';
    document.getElementById('deviceSection').style.display = 'none';
    document.getElementById('dashboardContainer').style.display = 'none';
    document.getElementById('cleanCard').style.display = 'none';
    document.getElementById('loadingBar').style.width = '0%';
    for (let i = 1; i <= 5; i++) {
        const s = document.getElementById('step' + i);
        s.classList.remove('active', 'completed');
    }
    uploadOuter.style.display = 'flex';
    fileInput.value = '';
}

// ============ ERRO ============
function showError(msg) {
    const err = document.getElementById('errorCard');
    err.textContent = 'ERRO: ' + msg;
    err.style.display = 'block';
}

// ============ PROCESSAMENTO DO ARQUIVO ============
function startScan(file) {
    if (!file) return;
    resetUI();

    const name = file.name.toLowerCase();
    const isTxt = name.endsWith('.txt');
    const isZip = name.endsWith('.zip');
    const isTarGz = name.endsWith('.tar.gz') || name.endsWith('.tgz') || name.endsWith('.gz');

    if (!isTxt && !isZip && !isTarGz) {
        showError('Formato inválido. Envie um arquivo .zip, .tar.gz/.tgz ou .txt (bugreport/dumpsys).');
        return;
    }

    currentFileInfo = { name: file.name, size: file.size };
    document.getElementById('progressContainer').style.display = 'block';
    uploadOuter.style.display = 'none';

    if (isTxt) {
        const reader = new FileReader();
        reader.onprogress = (e) => {
            if (e.lengthComputable) {
                const pct = Math.round((e.loaded / e.total) * 60);
                updateStep(1, 'active');
                showLoadingBar(pct);
            }
        };
        reader.onload = () => {
            updateStep(1, 'completed');
            readAndroidArchiveFiles({ paths: [file.name], read: (p) => Promise.resolve(reader.result) });
        };
        reader.onerror = () => showError('Não foi possível ler o arquivo.');
        reader.readAsText(file);
        return;
    }

    if (isZip) {
        if (typeof JSZip === 'undefined') {
            showError('Falha ao carregar biblioteca de leitura de .zip. Verifique sua conexão.');
            return;
        }
        const bufPromise = file.arrayBuffer();
        updateStep(1, 'active');
        bufPromise.then(buf => {
            updateStep(1, 'completed');
            updateStep(2, 'active');
            JSZip.loadAsync(buf).then(zip => {
                const allPaths = Object.keys(zip.files).filter(p => !zip.files[p].dir);
                updateStep(2, 'completed');
                readAndroidArchiveFiles({
                    paths: allPaths,
                    read: (p) => zip.file(p).async('string')
                });
            }).catch(() => showError('Arquivo .zip inválido ou corrompido.'));
        }).catch(() => showError('Não foi possível ler o arquivo.'));
        return;
    }

    if (isTarGz) {
        if (typeof pako === 'undefined') {
            showError('Falha ao carregar biblioteca de leitura de .tar.gz. Verifique sua conexão.');
            return;
        }
        updateStep(1, 'active');
        file.arrayBuffer().then(buf => {
            updateStep(1, 'completed');
            updateStep(2, 'active');
            try {
                const gzBytes = new Uint8Array(buf);
                showLoadingBar(30);
                const tarBytes = pako.ungzip(gzBytes);
                updateStep(2, 'completed');
                const entries = parseTar(tarBytes);
                const fileMap = {};
                const decoder = new TextDecoder('utf-8', { fatal: false });
                entries.forEach(entry => { if (!entry.dir) fileMap[entry.name] = entry.data; });
                const allPaths = Object.keys(fileMap);
                readAndroidArchiveFiles({
                    paths: allPaths,
                    read: (p) => Promise.resolve(decoder.decode(fileMap[p]))
                });
            } catch (e) {
                showError('Arquivo .tar.gz inválido ou corrompido.');
            }
        }).catch(() => showError('Não foi possível ler o arquivo.'));
        return;
    }
}
