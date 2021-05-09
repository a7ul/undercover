#!/usr/bin/env zx

import crypto from "crypto";
import path from "path";

const ENCRYPTION_DELIMITER = ".";
const ENC_DOT_ENV_EXT = ".ecrypt";
const ENC_OTHER_EXT = ".crypt";

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

function detectFileType(filename) {
  if (/.(env|env.*)$/g.test(filename)) {
    return "ENV_FILE";
  }
  if (filename.endsWith(ENC_DOT_ENV_EXT)) {
    return "ENCRYPTED_ENV_FILE";
  }
  if (filename.endsWith(ENC_OTHER_EXT)) {
    return "ENCRYPTED_OTHER_FILE";
  }
  return "OTHER_FILE";
}

async function getFile(file) {
  const stat = await fs.stat(file);
  if (stat.isFile()) {
    return { file, stat, detectedType: detectFileType(file) };
  }
  return { file, stat };
}

async function getFiles(directoryOrFile) {
  const results = [];
  try {
    // If file
    const rootStat = await fs.stat(directoryOrFile);
    if (rootStat.isFile()) {
      results.push({
        file: directoryOrFile,
        detectedType: detectFileType(directoryOrFile),
      });
      return results;
    }
    // If directory
    const fileNames = await fs.readdir(directoryOrFile);
    await Promise.all(
      fileNames.map(async (fileName) => {
        const file = path.join(directoryOrFile, fileName);
        const stat = await fs.stat(file);
        if (stat.isFile()) {
          results.push({ file, detectedType: detectFileType(file) });
        }
      })
    );
    return results;
  } catch (err) {
    console.error(err);
  } finally {
    return results;
  }
}

async function update() {
  const UPDATE_URL = "http://google.com"; //TODO: replace this with main
  const currentFile = import.meta.url.replace("file://", "");
  const resp = await fetch(UPDATE_URL);
  if (resp.ok) {
    const script = await resp.text();
    await fs.writeFile(currentFile, script, { encoding: "utf8", flag: "w" });
    chalk.green("Updated successfully! 🚀");
  }
}

// -------------------------

async function ask(q = "Question?", choices = []) {
  let ques = q + " ";
  const allChoices = choices.join("\n");
  if (allChoices) {
    ques = q + "\n" + allChoices + "\n> ";
  }
  const choice = await question(ques, { choices }).catch((e) => e);
  return choice;
}

// let answer = await ask(chalk`{magenta Yolo:}`);
// answer = await ask(chalk`{magenta Choices:}`, [`1. Hello`, `2. Yello`]);
// console.log({ answer });

// ./secrets.mjs encrypt ./env
// ./secrets.mjs encrypt -f ./env
// ./secrets.mjs encrypt -e ./env
// ./secrets.mjs decrypt ./env
// ./secrets.mjs help

function processArgs() {
  const args = process.argv.slice(3);
  const options = {};
  const positional = [];

  for (const arg of args) {
    if (arg.startsWith("-") || arg.startsWith("--")) {
      const [key, ...values] = arg.split("=");
      const value = values.join("=");
      options[key] = value || "true";
    } else {
      positional.push(arg);
    }
  }
  return { options, positional };
}

function helpCommand() {
  console.log(chalk`
{bold.underline Usage:} {bold ./undercover.mjs} {magenta <command> [options]} <file> | <dir>

{bold.underline Command:}

{bold.magenta encrypt:} {bold ./undercover.mjs} {magenta encrypt [-f | -e]} <file> | <dir>
{visible
  Encrypts the file using a secret. 
  If the file is detected as a dot env file, then only the values are encrypted and keys are left in plain text. 
  This makes it easy to see changes in the git diff.
  For any other file encrypts the entire file. Useful for things like service accounts, ssh keys etc.
}
  <file> {visible encrypt this file.}
  <dir>  {visible encrypt all files in this directory.}
  -f     {visible force encrypt entire file.}
  -e     {visible force encrypt a file as if it was an env file. Encrypt only the values.}
 
{bold.magenta decrypt:} {bold ./undercover.mjs} {magenta decrypt} <file.crypt> | <file.ecrypt> | <dir>
{visible
  Decrypts the file using the secret provided in the prompt
  For any other file encrypts the entire file. Useful for things like service accounts, ssh keys etc.
}
  <dir>  {visible decrypt all files in this directory.}

{bold.magenta update:} {bold ./undercover.mjs} {magenta update}
{visible
  Update this script to latest available version
}  

{bold.magenta help:} {bold ./undercover.mjs} {magenta help}
{visible
  Show this help text
}`);
}

async function main() {
  const { options, positional } = processArgs();
  // console.log({ options, positional });
  console.log(chalk`
🕵️  {bold.green Undercover}: {visible Store your environment variables and secrets in git safely.}
  `);

  const command = positional[0];
  switch (command) {
    case "encrypt":
      break;
    case "decrypt":
      break;
    case "help":
      return helpCommand();
    default:
      console.error(chalk`{bold.red Error:} {red ${command ? `Unknown command ${command}`: `No command specified!`}}\n`);
      console.error(chalk`For help: {bold ./undercover.mjs} {bold.magenta help}`);
      process.exit(-1);
  }
  // const secretDirOrFile = positional[1] || ".";
  // const files = await getFiles(secretDirOrFile);
  // console.log({ files });
}

await main();
