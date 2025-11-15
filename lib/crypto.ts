export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array
) {
  const enc = new TextEncoder();

  //   turn password into bytes
  //   "mypassword123" → [109, 121, 112, 97, 115, 115, ...]
  const baseKey = await crypto.subtle.importKey(
    "raw", //the key is raw bytes
    enc.encode(password), //your password as bytes
    "PBKDF2", //algorithm for deriving keys
    false, //cannot export key
    ["deriveKey"] //what operations are allowed
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array(salt).buffer as ArrayBuffer,
      iterations: 250000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptSeed(seed: Uint8Array, password: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPassword(password, salt);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new Uint8Array(seed).buffer as ArrayBuffer
  );
  return {
    ct: arrayBufferToBase64(ct),
    iv: bufferToBase64(iv),
    salt: bufferToBase64(salt),
  };
}

export async function decryptSeed(
  data: { ct: string; iv: string; salt: string },
  password: string
) {
  const iv = base64ToUint8(data.iv);
  const salt = base64ToUint8(data.salt);
  const key = await deriveKeyFromPassword(password, salt);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      base64ToArrayBuffer(data.ct)
    );
    return new Uint8Array(pt);
  } catch (e) {
    throw new Error("Incorrect password or corrupted data");
  }
}

// small helpers
function bufferToBase64(buf: Uint8Array) {
  return btoa(String.fromCharCode(...Array.from(buf)));
}

function arrayBufferToBase64(ab: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(ab)));
}

function base64ToUint8(s: string) {
  return new Uint8Array(
    atob(s)
      .split("")
      .map((c) => c.charCodeAt(0))
  );
}

function base64ToArrayBuffer(s: string): ArrayBuffer {
  const bytes = base64ToUint8(s);
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}
