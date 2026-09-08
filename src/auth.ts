// Web Crypto API を使ったステートレスな HMAC-SHA256 トークン生成・検証

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function getCryptoKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

/**
 * 24時間有効な管理用トークンを生成
 */
export async function generateToken(secret: string): Promise<string> {
  const key = await getCryptoKey(secret);
  const now = Math.floor(Date.now() / 1000);
  const payload = JSON.stringify({
    role: 'admin',
    iat: now,
    exp: now + 24 * 60 * 60, // 24時間
  });

  const enc = new TextEncoder();
  const payloadBytes = enc.encode(payload);
  const payloadB64 = base64UrlEncode(payloadBytes);

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(payloadB64)
  );
  const sigB64 = base64UrlEncode(new Uint8Array(signature));

  return `${payloadB64}.${sigB64}`;
}

/**
 * トークンの検証 (または ADMIN_SECRET の直接一致)
 */
export async function verifyToken(token: string | null | undefined, secret: string): Promise<boolean> {
  if (!token || !secret) {
    return false;
  }

  // 直接 ADMIN_SECRET が渡された場合（APIスクリプト等の利便性）
  if (token === secret) {
    return true;
  }

  try {
    const parts = token.split('.');
    if (parts.length !== 2) {
      return false;
    }

    const [payloadB64, sigB64] = parts;
    const key = await getCryptoKey(secret);
    const enc = new TextEncoder();
    const sigBytes = base64UrlDecode(sigB64);

    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      enc.encode(payloadB64)
    );

    if (!isValid) {
      return false;
    }

    const payloadJson = new TextDecoder().decode(base64UrlDecode(payloadB64));
    const payload = JSON.parse(payloadJson);
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now) {
      return false; // 有効期限切れ
    }

    return true;
  } catch {
    return false;
  }
}
