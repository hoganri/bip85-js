import test from "ava";
const bejs = require(".");

test("BIP39 mnemonic to entropy", async (t) => {
  const path = "m/83696968'/0'/0'";
  const mnemonic =
    "install scatter logic circle pencil average fall shoe quantum disease suspect usage";
  const res = await bejs.bip39MnemonicToEntropy(path, mnemonic);
  t.is(
    res.toString("hex"),
    "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
  );
});

test("BIP39 mnemonic to entropy (with passphrase)", async (t) => {
  const path = "m/83696968'/0'/0'";
  const mnemonic =
    "install scatter logic circle pencil average fall shoe quantum disease suspect usage";
  const passphrase = "TREZOR";
  const res = await bejs.bip39MnemonicToEntropy(path, mnemonic, passphrase);
  t.is(
    res.toString("hex"),
    "d24cee04c61c4a47751658d078ae9b0cc9550fe43eee643d5c10ac2e3f5edbca757b2bd74d55ff5bcc2b1608d567053660d9c7447ae1eb84b6619282fd391844"
  );
});

test("xprv to entropy", (t) => {
  const path = "m/83696968'/0'/0'";
  const XPRV =
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

  t.is(
    bejs.bip32XPRVToEntropy(path, XPRV).toString("hex"),
    "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
  );
});

test("entropy to mnemonic", (t) => {
  const path = "m/83696968'/0'/0'";
  const XPRV =
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

  const entropy = bejs.bip32XPRVToEntropy(path, XPRV);

  const words12 =
    "useful guitar veteran zone perfect october explain grant clarify december flight recycle";
  t.is(bejs.entropyToBIP39(entropy, 12), words12);

  const words15 =
    "useful guitar veteran zone perfect october explain grant clarify december flight raw banana estate uncle";
  t.is(bejs.entropyToBIP39(entropy, 15), words15);

  const words24 =
    "useful guitar veteran zone perfect october explain grant clarify december flight raw banana estate unfair grow search witness echo market primary alley forward boring";
  t.is(bejs.entropyToBIP39(entropy, 24), words24);
});

test("wif from entropy", async (t) => {
  const path = "m/83696968'/2'/0'";
  const XPRV =
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

  const entropy = bejs.bip32XPRVToEntropy(path, XPRV);

  let res = await bejs.entropyToWif(entropy);
  t.is(res, "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp");

  res = bejs.entropyFromWif(
    "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
  );
  t.is(res.toString("hex"), entropy.slice(0, 32).toString("hex"));
});

test("test BIP32 to mnemonic BIP39", async (t) => {
  let path, entropy, mnemonic;
  const XPRV =
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

  path = "m/83696968'/39'/0'/12'/0'";
  entropy = bejs.bip32XPRVToEntropy(path, XPRV);
  mnemonic = bejs.entropyToBIP39(entropy, 12);
  t.is(
    entropy.slice(0, 16).toString("hex"),
    "6250b68daf746d12a24d58b4787a714b"
  );
  t.is(
    mnemonic,
    "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
  );

  path = "m/83696968'/39'/0'/18'/0'";
  entropy = bejs.bip32XPRVToEntropy(path, XPRV);
  mnemonic = bejs.entropyToBIP39(entropy, 18);
  t.is(
    entropy.slice(0, 24).toString("hex"),
    "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc"
  );
  t.is(
    mnemonic,
    "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"
  );

  path = "m/83696968'/39'/0'/24'/0'";
  entropy = bejs.bip32XPRVToEntropy(path, XPRV);
  mnemonic = bejs.entropyToBIP39(entropy, 24);
  t.is(
    entropy.slice(0, 32).toString("hex"),
    "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f"
  );
  t.is(
    mnemonic,
    "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"
  );
});

test("test XPRV to XPRV", async (t) => {
  const path = "83696968'/32'/0'";
  const XPRV =
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

  let res = bejs.bip32XPRVToXPRV(path, XPRV);
  t.is(
    res,
    "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
  );
});

test("test XPRV to hex", async (t) => {
  let path, width;
  const XPRV =
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

  path = "83696968'/128169'/32'/0'";
  width = 32;
  t.is(
    await bejs.bip32XPRVToHex(path, width, XPRV),
    "ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc"
  );

  path = "83696968'/128169'/64'/0'";
  width = 64;
  t.is(
    await bejs.bip32XPRVToHex(path, width, XPRV),
    "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
  );

  path = "83696968'/128169'/64'/1234'";
  width = 64;
  t.is(
    await bejs.bip32XPRVToHex(path, width, XPRV),
    "61d3c182f7388268463ef327c454a10bc01b3992fa9d2ee1b3891a6b487a5248793e61271066be53660d24e8cb76ff0cfdd0e84e478845d797324c195df9ab8e"
  );
});

test("test bipentropyjs applications", async (t) => {
  const XPRV =
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
  const app = bejs.app;

  const res = await app.bip39(XPRV, "english", 18, 0);
  t.is(
    res,
    "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"
  );

  t.is(
    app.xprv(XPRV, 0),
    "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
  );

  t.is(
    await app.wif(XPRV, 0),
    "Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp"
  );

  t.is(
    await app.hex(XPRV, 0, 32),
    "ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc"
  );
});

test("test bipentropyjs extras", async (t) => {
  const XPRV =
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
  const extras = bejs.extras;

  t.is(
    await extras.bip32ToCrippleSeed("m/574946'/0'", XPRV),
    "ssyKPX1uyL4mTpba6hHDRTX2Cj6gT"
  );
});
