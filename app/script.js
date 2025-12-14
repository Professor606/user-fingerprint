function sha256(obj) {
  const str = JSON.stringify(obj);
  
  function utf8Encode(str) {
    return unescape(encodeURIComponent(str));
  }

  function rotr(n, x) {
    return (x >>> n) | (x << (32 - n));
  }

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const msg = utf8Encode(str);
  const msgLen = msg.length;
  const bitLen = msgLen * 8;
  
  const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  
  for (let i = 0; i < msgLen; i++) {
    padded[i] = msg.charCodeAt(i);
  }

  padded[msgLen] = 0x80;
  
  for (let i = 0; i < 8; i++) {
    padded[paddedLen - 1 - i] = (bitLen >>> (i * 8)) & 0xff;
  }
  
  for (let offset = 0; offset < paddedLen; offset += 64) {
    const W = new Array(64);
    
    for (let i = 0; i < 16; i++) {
      W[i] = (padded[offset + i * 4] << 24) |
             (padded[offset + i * 4 + 1] << 16) |
             (padded[offset + i * 4 + 2] << 8) |
             (padded[offset + i * 4 + 3]);
    }

    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, W[i - 15]) ^ rotr(18, W[i - 15]) ^ (W[i - 15] >>> 3);
      const s1 = rotr(17, W[i - 2]) ^ rotr(19, W[i - 2]) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }

    let [a, b, c, d, e, f, g, h] = H;
    
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) | 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;
    
      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    H[0] = (H[0] + a) | 0;
    H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0;
    H[5] = (H[5] + f) | 0;
    H[6] = (H[6] + g) | 0;
    H[7] = (H[7] + h) | 0;
  }
  
  return H.map(h => ('00000000' + (h >>> 0).toString(16)).slice(-8)).join('');
}

async function getClientInfoAndHashes() {
  const info = {};

  // Browser fingerprint data
  info.userAgent = navigator.userAgent;
  info.platform = navigator.platform;
  info.doNotTrack = navigator.doNotTrack;
  info.javaEnabled = navigator.javaEnabled?.() || false;
  
  // Device fingerprint data
  info.hardwareConcurrency = navigator.hardwareConcurrency || 'unknown';
  info.deviceMemory = navigator.deviceMemory || 'unknown';
  info.screen = {
    width: screen.width,
    height: screen.height,
    availWidth: screen.availWidth,
    availHeight: screen.availHeight,
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth
  };

  // Languages fingerprint data
  info.language = navigator.language;
  info.languages = navigator.languages;

  // Window fingerprint data
  info.window = {
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,
    devicePixelRatio: window.devicePixelRatio
  };

  // Timezone fingerprint data
  info.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  info.localTime = new Date().toTimeString();

  // IP fingerprint data
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch('/api/ipinfo', { 
      signal: controller.signal,
      headers: {
        'Accept': 'application/json'
      }
    });
    
    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }

    const data = await response.json();

    info.ip = data.ip;
    info.ipLocation = {
      city: data.city || 'Unknown',
      region: data.region || 'Unknown',
      country: data.country || 'Unknown',
      loc: data.loc || null,
      org: data.org || 'Unknown',
      postal: data.postal || 'Unknown',
      timezone: data.timezone || 'Unknown'
    };
  } catch (error) {
    if (error.name === "AbortError") {
      console.warn("IP fetch timed out");
    } else {
      console.error("IP fetch failed:", error);
    }

    info.ip = "Unavailable";
    info.ipLocation = {
      city: 'Unknown',
      region: 'Unknown',
      country: 'Unknown',
      loc: null,
      org: 'Unknown',
      postal: 'Unknown',
      timezone: 'Unknown'
    };
  }

  // Group 1: Browser fingerprint data
  const group1 = {
    userAgent: info.userAgent,
    platform: info.platform,
    doNotTrack: info.doNotTrack,
    javaEnabled: info.javaEnabled
  };

  // Group 2: Device fingerprint data
  const group2 = {
    hardwareConcurrency: info.hardwareConcurrency,
    deviceMemory: info.deviceMemory,
    screen: info.screen
  };

  // Group 3: Languages fingerprint data
  const group3 = {
    language: info.language,
    languages: info.languages
  };

  // Group 4: Window fingerprint data
  const group4 = info.window;

  // Group 5: Timezone fingerprint data
  const group5 = {
    timezone: info.timezone
  };

  // Group 6: IP fingerprint data
  const group6 = {
    ip: info.ip,
    ipLocation: info.ipLocation
  };

  // Hash each group
  const hash1 = sha256(group1);
  const hash2 = sha256(group2);
  const hash3 = sha256(group3);
  const hash4 = sha256(group4);
  const hash5 = sha256(group5);
  const hash6 = info.ip == "Unavailable" ? "" : sha256(group6);

  return {
    info,
    hashes: {
      browserFingerprint: hash1,
      deviceFingerprint: hash2,
      languagesFingerprint: hash3,
      windowFingerprint: hash4,
      timeZoneFingerprint: hash5,
      ipFingerprint: hash6,
    }
  };
}

const sendData = async (info) => {
  const payload = {
    timestamp: new Date().toISOString(),
    fingerprints: info
  };

  try {
    const response = await fetch('/api/data', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

  } catch (error) {
    console.error('Network error:', error);
  }
};

window.addEventListener('DOMContentLoaded', async () => {
  const result = await getClientInfoAndHashes();
  sendData(result.hashes);
  
  const display = document.getElementById('display');
  if (display) display.textContent = JSON.stringify(result, null, 2);
});