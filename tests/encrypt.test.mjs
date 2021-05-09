import assert from "assert";
import { test } from "./lib.mjs";

import { encrypt, decrypt, getSecretKey } from "../undercover.mjs";

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

test("encrypt and decrypt a text with new lines", () => {
  const text = `
    Hello 
    World
    `;
  const encrypted = encrypt(text, secretKey);
  const decrypted = decrypt(encrypted, secretKey);
  assert.strictEqual(decrypted, text);
});
