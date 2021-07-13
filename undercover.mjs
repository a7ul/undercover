#!/usr/bin/env node

// :=================================:
// : ./undercover.mjs                :
// : Author: Atul <github.com/a7ul>  :
// : License: MIT                    :
// :=================================:

import crypto from "crypto";
import readline from "readline";
import path from "path";
import { spawn } from "child_process";
import fs from "fs/promises";

const ENCRYPTION_DELIMITER = ".";
const ENC_ENV_EXT = ".ecrypt";
const ENC_OTHER_EXT = ".crypt";

const FILE_TYPE = {
  ENC: {
    ENV: "ENCRYPTED_ENV_FILE",
    OTHER: "ENCRYPTED_OTHER_FILE",
  },
  REGULAR: {
    ENV: "REGULAR_ENV_FILE",
    OTHER: "REGULAR_OTHER_FILE",
  },
};

// Utlities

function shellEscape(arg) {
  if (/^[a-z0-9_.-/]+$/i.test(arg)) {
    return arg;
  }
  return (
    `$'` +
    arg
      .replace(/\\/g, "\\\\")
      .replace(/'/g, "\\'")
      .replace(/\f/g, "\\f")
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r")
      .replace(/\t/g, "\\t")
      .replace(/\v/g, "\\v")
      .replace(/\0/g, "\\0") +
    `'`
  );
}

function execute(command) {
  const child = spawn(command, { shell: true, windowsHide: true });
  if (process.stdin.isTTY) {
    process.stdin.pipe(child.stdin);
  }
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  return new Promise((resolve, reject) => {
    child.on("exit", (code) => {
      const result = code === 0 ? resolve : reject;
      result({ code, stdout, stderr });
    });
  });
}

function isEqualStr(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  return a.localeCompare(b) === 0;
}

function detectFileType(filepath) {
  const f = path.basename(filepath);
  const ext = path.extname(f);
  if (ext === ENC_ENV_EXT) {
    return FILE_TYPE.ENC.ENV;
  }
  if (ext === ENC_OTHER_EXT) {
    return FILE_TYPE.ENC.OTHER;
  }
  if (ext === ".env" || f.startsWith(".env." || f === ".env")) {
    return FILE_TYPE.REGULAR.ENV;
  }
  return FILE_TYPE.REGULAR.OTHER;
}

function getDestFile(file) {
  switch (file.type) {
    case FILE_TYPE.ENC.ENV:
      return {
        filepath: file.filepath.slice(0, -ENC_ENV_EXT.length),
        type: FILE_TYPE.REGULAR.ENV,
      };
    case FILE_TYPE.ENC.OTHER:
      return {
        filepath: file.filepath.slice(0, -ENC_OTHER_EXT.length),
        type: FILE_TYPE.REGULAR.OTHER,
      };
    case FILE_TYPE.REGULAR.ENV:
      return {
        filepath: `${file.filepath}${ENC_ENV_EXT}`,
        type: FILE_TYPE.ENC.ENV,
      };
    case FILE_TYPE.REGULAR.OTHER:
      return {
        filepath: `${file.filepath}${ENC_OTHER_EXT}`,
        type: FILE_TYPE.ENC.OTHER,
      };
  }
  throw new Error(`Unsupported file type: ${file.type}: ${file.filepath}`);
}

function printTitle() {
  console.log(
    `\n🕵️  Undercover: Store your environment variables and secrets in git safely.`
  );
}

class OrderedKeyVal {
  store = {};
  set(key, val) {
    this.store[key] = this.store[key] ?? [];
    this.store[key].push(val);
  }
  get(key) {
    this.store[key] = this.store[key] ?? [];
    return this.store[key].shift();
  }
}

function dotEnvFileTransformer(
  fileContent = "",
  processEnvLine = (key, value) => [key, value].join("=")
) {
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
    return processEnvLine(key, value);
  });
  return transformedLines.join("\n");
}

async function getFiles(fileOrDirectoryNames) {
  const results = [];
  try {
    for (const fileOrDirName of fileOrDirectoryNames) {
      const stat = await fs.stat(fileOrDirName);
      if (stat.isFile()) {
        results.push(fileOrDirName);
      } else if (stat.isDirectory()) {
        const filesInDir = await fs.readdir(fileOrDirName);
        await Promise.all(
          filesInDir.map(async (f) => {
            const filePath = path.join(fileOrDirName, f);
            const fileStat = await fs.stat(filePath);
            if (fileStat.isFile()) {
              results.push(filePath);
            }
          })
        );
      }
    }
  } catch (err) {
    console.error(err);
  }
  return results.map((filepath) => ({
    filepath,
    type: detectFileType(filepath),
  }));
}

async function ask(q = "Question?", choices = []) {
  let ques = q + " ";
  const allChoices = choices.join("\n");
  if (allChoices) {
    ques = q + "\n" + allChoices + "\n> ";
  }
  const { stdin, stdout } = process;
  const rl = readline.createInterface({ input: stdin, output: stdout });
  return new Promise((resolve) => {
    rl.question(ques, function (answer) {
      resolve(answer);
      rl.close();
    });
  });
}
async function askPassword() {
  const { stdin, stdout } = process;
  const rl = readline.createInterface({ input: stdin, output: stdout });
  rl.input.on("keypress", function (c, k) {
    const len = rl.line.length;
    readline.moveCursor(rl.output, -len, 0);
    readline.clearLine(rl.output, 1);
    for (var i = 0; i < len; i++) {
      rl.output.write("*");
    }
  });
  return new Promise((resolve) => {
    rl.question(`\n🔑 Enter password\n> `, function (password) {
      resolve(password);
      rl.close();
    });
  });
}

function processArgs(args) {
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

async function showDiff(encFile, secretKey) {
  let content = await fs.readFile(encFile.filepath, { encoding: "utf-8" });
  if (encFile.type === FILE_TYPE.ENC.ENV) {
    content = decryptDotEnvContent(content, secretKey).trim();
  } else if (encFile.type === FILE_TYPE.ENC.OTHER) {
    content = decrypt(content, secretKey).trim();
  }
  const originalFile = getDestFile(encFile);
  console.log(`Diffing ${encFile.filepath} <-> ${originalFile.filepath} 👀`);

  const output = await execute(
    `git --no-pager diff --color $(echo ${shellEscape(
      content
    )} | git hash-object -w --stdin) ${shellEscape(originalFile.filepath)}`
  );

  if (!output.stdout && !output.stderr) {
    console.log(`\nNo changes ✨\n`);
  } else {
    console.log(output.stderr);
    console.log(output.stdout);
  }
}

// Encryption

export function getSecretKey(password) {
  return crypto.createHash("sha256").update(password).digest();
}

export function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(key), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ENCRYPTION_DELIMITER + encrypted.toString("hex");
}

export function decrypt(encrypted, key) {
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

export function encryptIfChanged(text, previouslyEncrypted, key) {
  if (!previouslyEncrypted) {
    return encrypt(text, key);
  }
  let previousText = "";
  try {
    previousText = decrypt(previouslyEncrypted, key);
  } catch (err) {
    console.warn(err);
  }
  if (isEqualStr(text, previousText)) {
    return previouslyEncrypted;
  } else {
    return encrypt(text, key);
  }
}

async function encryptFile(srcFile, secretKey) {
  let content = await fs.readFile(srcFile.filepath, { encoding: "utf-8" });
  const destFile = getDestFile(srcFile);
  const existingEncrypted = await fs
    .readFile(destFile.filepath, { encoding: "utf-8" })
    .catch((err) => null);

  switch (srcFile.type) {
    case FILE_TYPE.REGULAR.ENV: {
      console.log(
        `Encrypting values in ${srcFile.filepath} -> ${destFile.filepath} 🔏`
      );
      const existingKeyVal = new OrderedKeyVal();
      if (existingEncrypted) {
        dotEnvFileTransformer(existingEncrypted, (k, v) => {
          existingKeyVal.set(k, v);
        });
      }
      const processEnvLine = (k, v) =>
        [k, encryptIfChanged(v, existingKeyVal.get(k), secretKey)].join("=");
      content = dotEnvFileTransformer(content, processEnvLine);
      break;
    }
    case FILE_TYPE.REGULAR.OTHER: {
      console.log(
        `Encrypting file ${srcFile.filepath} -> ${destFile.filepath} 🔐`
      );
      content = encryptIfChanged(content, existingEncrypted, secretKey);
      break;
    }
  }
  await fs.writeFile(destFile.filepath, content);
}

function decryptDotEnvContent(content, secretKey) {
  const processEnvLine = (key, value) =>
    [key, decrypt(value, secretKey)].join("=");
  return dotEnvFileTransformer(content, processEnvLine);
}

async function decryptFile(srcFile, secretKey) {
  let content = await fs.readFile(srcFile.filepath, { encoding: "utf-8" });
  const destFile = getDestFile(srcFile);

  switch (srcFile.type) {
    case FILE_TYPE.ENC.ENV: {
      console.log(
        `Decrypting values in ${srcFile.filepath} -> ${destFile.filepath} 🔓`
      );
      content = decryptDotEnvContent(content, secretKey);
      break;
    }
    case FILE_TYPE.ENC.OTHER: {
      console.log(
        `Decrypting file ${srcFile.filepath} -> ${destFile.filepath} 🔓`
      );
      content = decrypt(content, secretKey);
      break;
    }
  }

  await fs.writeFile(destFile.filepath, content);
}

// Commands

async function encryptCommand(args) {
  const { options, positional: inputFileNames } = processArgs(args);
  const files = await getFiles(inputFileNames);

  let filesToEncrypt = files.filter((f) =>
    [FILE_TYPE.REGULAR.ENV, FILE_TYPE.REGULAR.OTHER].includes(f.type)
  );

  if (options["-f"] === "true") {
    filesToEncrypt = filesToEncrypt.map((f) => ({
      ...f,
      type: FILE_TYPE.REGULAR.OTHER,
    }));
  } else if (options["-e"] === "true") {
    filesToEncrypt = filesToEncrypt.map((f) => ({
      ...f,
      type: FILE_TYPE.REGULAR.ENV,
    }));
  }

  if (filesToEncrypt.length === 0) {
    return console.log(`No files found to encrypt 😢`);
  }

  const password = await askPassword();
  const secretKey = getSecretKey(password);

  for (const fileToEncrypt of filesToEncrypt) {
    await encryptFile(fileToEncrypt, secretKey);
  }

  console.log(`\nAll files encrypted successfully ✅`);
}

async function decryptCommand(args) {
  const { options, positional: inputFiles } = processArgs(args);
  const files = await getFiles(inputFiles);

  let filesToDecrypt = files.filter((f) =>
    [FILE_TYPE.ENC.OTHER, FILE_TYPE.ENC.ENV].includes(f.type)
  );

  if (filesToDecrypt.length === 0) {
    return console.log(`No files to decrypt 😢`);
  }

  const password = await askPassword();
  const secretKey = getSecretKey(password);

  for (const fileToDecrypt of filesToDecrypt) {
    await decryptFile(fileToDecrypt, secretKey);
  }

  console.log(`\nAll files decrypted successfully ✅`);
}

async function diffCommand(args) {
  const { options, positional: fileNames } = processArgs(args);
  const files = await getFiles(fileNames);

  let filesToDiff = files.filter((f) =>
    [FILE_TYPE.ENC.OTHER, FILE_TYPE.ENC.ENV].includes(f.type)
  );

  if (filesToDiff.length === 0) {
    return console.log(`\nNo files found to diff 😢`);
  }

  const password = await askPassword();
  const secretKey = getSecretKey(password);

  for (const file of filesToDiff) {
    await showDiff(file, secretKey);
  }
}

async function updateCommand() {
  const answer = await ask(
    `✨ This will update undercover to latest version. Continue?`,
    [`yes`, `no`]
  );
  if (!answer.toLowerCase().trim().startsWith("y")) {
    return;
  }
  const UPDATE_URL =
    "https://raw.githubusercontent.com/a7ul/undercover/main/undercover.mjs";
  const currentFilePath = import.meta.url.replace("file://", "");
  const resp = await fetch(UPDATE_URL);
  if (resp.ok) {
    const script = await resp.text();
    await fs.writeFile(currentFilePath, script, {
      encoding: "utf8",
      flag: "w",
    });
    console.log("Updated successfully! ✅");
  } else {
    console.error(`Failed to update! 😢`, await resp.text());
    process.exit(-1);
  }
}

function helpCommand() {
  printTitle();
  console.log(`
📖 Usage: ./undercover.mjs <command> [options] <file...> | <dir...>

Commands:
---------

🔐 encrypt: undercover.mjs encrypt [-f | -e] <file...> | <dir...>

   Encrypts the file using a secret. 
   If the file is detected as a dot env file, then only the values are encrypted and keys are left in plain text. 
   This makes it easy to see changes in the git diff.
   For any other file encrypts the entire file. Useful for things like service accounts, ssh keys etc.

   <file>  encrypt this file.
   <dir>   encrypt all files in this directory.
   -f      force encrypt entire file.
   -e      force encrypt a file as if it was an env file. Encrypt only the values.
 
🔓 decrypt: undercover.mjs decrypt <file.crypt...> | <file.ecrypt...> | <dir...>

   Decrypts the file using the secret provided in the prompt.
   For any other file encrypts the entire file. Useful for things like service accounts, ssh keys etc.

   <dir>  decrypt all files in this directory.

👀 diff: undercover.mjs diff <file.crypt...> | <file.ecrypt...> | <dir...>

   Displays the diff between the input encrypted file and the original file.
   Useful for checking what will change in the encrypted file if you encrypt the original file now.

   <dir>  show diff for all encrypted files in this directory.
  
✨ update: undercover.mjs update

   Update this script to latest available version.  

💛 help: undercover.mjs help

   Show this help text.
`);
}

function unknownCommand(command) {
  printTitle();
  console.error(
    `\nError: ${
      command ? `Unknown command: ${command} 🤷` : `No command specified 😢`
    }\n`
  );
  console.error(`Try: undercover.mjs help`);
  process.exit(-1);
}

// Main

async function main() {
  const [command, ...args] = process.argv.slice(2);

  switch (command) {
    case "encrypt":
      await encryptCommand(args);
      break;
    case "decrypt":
      await decryptCommand(args);
      break;
    case "diff":
      await diffCommand(args);
      break;
    case "update":
      await updateCommand();
      break;
    case "help":
      helpCommand();
      break;
    default:
      unknownCommand(command);
  }
  process.exit(0);
}

if (process.env.NODE_ENV !== "test") {
  await main();
}
