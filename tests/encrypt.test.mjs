import assert from "assert";
import { test } from "./lib.mjs";

import {
  encrypt,
  decrypt,
  getSecretKey,
  encryptIfChanged,
} from "../undercover.mjs";

const secretKey = getSecretKey("qwerty");

test("encrypt and decrypt a text", () => {
  const text = "Hello";
  const encrypted = encrypt(text, secretKey);
  const decrypted = decrypt(encrypted, secretKey);
  assert.strictEqual(decrypted, text);
});

test("encrypt and decrypt a text with new lines", () => {
  const text = `
  Hello 
  World
  `;
  const encrypted = encrypt(text, secretKey);
  const decrypted = decrypt(encrypted, secretKey);
  assert.strictEqual(decrypted, text);
});

test("dont encrypt if not changed", () => {
  const text = `
    Hello 
    World
    `;
  const previouslyEncrypted = encryptIfChanged(text, "", secretKey);
  const encrypted = encryptIfChanged(text, previouslyEncrypted, secretKey);
  assert.strictEqual(previouslyEncrypted, encrypted);
});

test("encrypt if changed", () => {
  let text = `
    Hello 
    World
    `;
  const previouslyEncrypted = encryptIfChanged(text, "", secretKey);
  text += " ";
  const encrypted = encryptIfChanged(text, previouslyEncrypted, secretKey);
  assert.ok(previouslyEncrypted.localeCompare(encrypted) !== 0);
  assert.strictEqual(decrypt(encrypted, secretKey), text);
});
