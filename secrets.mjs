#!/usr/bin/env zx

import crypto from "crypto";

const ENCRYPTION_DELIMITER = ".";
const ENC_DOT_ENV_EXT = ".ecrypt";
const ENC_REGULAR_EXT = ".crypt";

function getSecretKey(password) {
  return crypto.createHash("sha256").update(password).digest();
}

function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ENCRYPTION_DELIMITER + encrypted.toString("hex");
}

function decrypt(encrypted, key) {
  const [ivPart, ...textParts] = encrypted.split(ENCRYPTION_DELIMITER);
  const iv = Buffer.from(ivPart, "hex");
  const encryptedText = Buffer.from(
    textParts.join(ENCRYPTION_DELIMITER),
    "hex"
  );
  const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(key), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

function dotEnvFileTransformer(fileContent = "", onValue = (value) => value) {
  const NEW_LINE_REGEX = /\n|\r|\r\n/;
  const content = fileContent.toString();
  const envLines = content.split(NEW_LINE_REGEX);

  const transformedLines = envLines.map((line) => {
    const isNotEnvLine = line.includes("=") == false;
    const isComment = line.trim().startsWith("#");
    if (isNotEnvLine || isComment) {
      return line;
    }
    const [key, ...valueParts] = line.split("=");
    const value = valueParts.join("=");
    const transformedValue = onValue(value);
    return [key, transformedValue].join("=");
  });
  return transformedLines.join("\n");
}

function encryptDotEnvFileValues(dotEnvFileContent, secretKey) {
  const onValue = (value) => encrypt(value, secretKey);
  return dotEnvFileTransformer(dotEnvFileContent, onValue);
}

function decryptDotEnvFileValues(dotEnvFileContent, secretKey) {
  const onValue = (value) => decrypt(value, secretKey);
  return dotEnvFileTransformer(dotEnvFileContent, onValue);
}

function encryptEntireFile(fileContent, secretKey) {
  const content = fileContent.toString();
  return encrypt(content, secretKey);
}

function decryptEntireFile(encryptedContent, secretKey) {
  const content = encryptedContent.toString();
  return decrypt(content, secretKey);
}

// -------------------------

async function test() {
  const secretKey = getSecretKey("YOLO");

  const content = await fs.readFile("./env/abc.env");
  const encrypted = encryptDotEnvFileValues(content, secretKey);
  await fs.writeFile(`./env/abc${ENC_DOT_ENV_EXT}`, encrypted);
  console.log("ENCRYPTED");

  const envContent = await fs.readFile(`./env/abc${ENC_DOT_ENV_EXT}`);
  const decryptedContent = decryptDotEnvFileValues(envContent, secretKey);
  console.log(decryptedContent);

  // console.log("ENTIRE FILE");
  // const encrypted2 = encryptEntireFile(content, secretKey);
  // console.log(encrypted2);
  // console.log("DECRYPTED");
  // console.log(decryptEntireFile(encrypted2, secretKey));
}

console.log(await test());
