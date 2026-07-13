import { webcrypto } from "node:crypto";

const crypto = webcrypto;
const input = JSON.parse(process.argv[2]);
const encoder = new TextEncoder();
const workerPublic = Buffer.from(input.workerPubKey, "base64");
const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
const workerKey = await crypto.subtle.importKey("raw", workerPublic, { name: "X25519" }, false, []);
const shared = await crypto.subtle.deriveBits({ name: "X25519", public: workerKey }, pair.privateKey, 256);
const salt = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(12));
const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({
  name: "HKDF",
  hash: "SHA-256",
  salt,
  info: encoder.encode(`pinchana-dlp/cookies/v2/${input.jobId}/${input.keyId}`),
}, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ciphertext = await crypto.subtle.encrypt({
  name: "AES-GCM",
  iv,
  additionalData: encoder.encode(`pinchana-dlp:v2:${input.jobId}:${input.keyId}`),
}, key, encoder.encode(input.plaintext));
console.log(JSON.stringify({
  version: 2,
  keyId: input.keyId,
  clientPubKey: Buffer.from(await crypto.subtle.exportKey("raw", pair.publicKey)).toString("base64"),
  salt: Buffer.from(salt).toString("base64"),
  iv: Buffer.from(iv).toString("base64"),
  ciphertext: Buffer.from(ciphertext).toString("base64"),
}));
