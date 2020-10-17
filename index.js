"use strict";
const wif = require("wif");
const bs58 = require("bs58");
const bip39 = require("bip39");
const bip32 = require("bip32");
const crypto = require("crypto");
const rs58 = require("ripple-bs58");

function hmacsha512(message) {
  return crypto
    .createHmac("sha512", "bip-entropy-from-k")
    .update(message)
    .digest();
}

function bip32XPRVToEntropy(path, xprvString) {
  const xprv = bip32.fromBase58(xprvString);
  const child = xprv.derivePath(path);
  return hmacsha512(child.privateKey);
}

async function bip39MnemonicToEntropy(path, mnemonic, passphrase) {
  const bip39Seed = await bip39.mnemonicToSeed(mnemonic, passphrase);
  const xprv = await bip32.fromSeed(bip39Seed);
  const child = xprv.derivePath(path);
  return hmacsha512(child.privateKey);
}

function entropyToBIP39(entropy, words, language = "english") {
  const width = Math.floor(((words - 1) * 11) / 8 + 1);
  return bip39.entropyToMnemonic(entropy.slice(0, width));
}

function entropyToWif(entropy) {
  const privateKey = Buffer.from(entropy.slice(0, 32));
  return wif.encode(128, privateKey, true);
}

function entropyFromWif(key) {
  return wif.decode(key).privateKey;
}

function calculateChecksum(extendedKey) {
  let hash = crypto.createHash("sha256");
  hash.update(extendedKey);
  let data = hash.digest();
  hash = crypto.createHash("sha256");
  hash.update(data);
  return hash.digest().slice(0, 4);
}

function bip32XPRVToXPRV(path, xprvString) {
  const ent = bip32XPRVToEntropy(path, xprvString);

  const prefix = Buffer.from("0488ade4", "hex");
  const depth = Buffer.from("00", "hex");
  const parentFingerprint = Buffer.from("00".repeat(4), "hex");
  const childNum = Buffer.from("00".repeat(4), "hex");
  const chainCode = ent.slice(0, 32);
  const privateKey = Buffer.concat(
    [Buffer.from("00", "hex"), Buffer.from(ent.slice(32, ent.length), "hex")],
    ent.length + 1
  );
  const extendedKey = Buffer.concat(
    [prefix, depth, parentFingerprint, childNum, chainCode, privateKey],
    78
  );
  const checksum = calculateChecksum(extendedKey);

  const bytes = Buffer.concat(
    [extendedKey, checksum],
    extendedKey.length + checksum.length
  );
  return bs58.encode(bytes);
}

async function bip32XPRVToHex(path, width, xprvString) {
  const entropy = await bip32XPRVToEntropy(path, xprvString);
  return entropy.slice(0, width).toString("hex");
}

function languageIdxOf(language) {
  const languages = [
    "english",
    "japanese",
    "korean",
    "spanish",
    "chinese_simplified",
    "chinese_traditional",
    "french",
    "italian",
    "czech",
  ];

  return languages.indexOf(language);
}

const app = {
  bip39: async function (xprvString, language, words, index) {
    const languageIdx = languageIdxOf(language);
    const path = `m/83696968'/39'/${languageIdx}'/${words}'/${index}'`;
    const entropy = await bip32XPRVToEntropy(path, xprvString);
    const res = await entropyToBIP39(entropy, words, language);
    return res;
  },
  xprv: function (xprvString, index) {
    const path = `83696968'/32'/${index}'`;
    return bip32XPRVToXPRV(path, xprvString);
  },
  wif: async function (xprvString, index) {
    const path = `m/83696968'/2'/${index}'`;
    const entropy = await bip32XPRVToEntropy(path, xprvString);
    return entropyToWif(entropy);
  },
  hex: async function (xprvString, index, width) {
    const path = `m/83696968'/128169'/${width}'/${index}'`;
    const res = await bip32XPRVToHex(path, width, xprvString);
    return res;
  },
};

function entropyToCrippleSeed(entropy) {
  const key = Buffer.concat(
    [Buffer.from("21", "hex"), entropy.slice(0, 16)],
    17
  );
  const checksum = calculateChecksum(key);
  const rawSeed = Buffer.concat([key, checksum], key.length + checksum.length);
  return rs58.encode(rawSeed);
}

async function bip32ToCrippleSeed(path, xprvString) {
  const entropy = await bip32XPRVToEntropy(path, xprvString);
  return entropyToCrippleSeed(entropy);
}

const extras = {
  entropyToCrippleSeed: entropyToCrippleSeed,
  bip32ToCrippleSeed: bip32ToCrippleSeed,
};

module.exports = {
  bip32XPRVToEntropy: bip32XPRVToEntropy,
  bip39MnemonicToEntropy: bip39MnemonicToEntropy,
  entropyToBIP39: entropyToBIP39,
  entropyToWif: entropyToWif,
  entropyFromWif: entropyFromWif,
  bip32XPRVToXPRV: bip32XPRVToXPRV,
  bip32XPRVToHex: bip32XPRVToHex,
  app: app,
  extras: extras,
};
