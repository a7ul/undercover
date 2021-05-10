#!/usr/bin/env zx

import crypto from "crypto";
import path from "path";
import { $ } from "zx";

const ENCRYPTION_DELIMITER = ".";
const ENC_ENV_EXT = ".ecrypt";
const ENC_OTHER_EXT = ".crypt";

const FILE_TYPE = {
  ENC_ENV: "ENCRYPTED_ENV_FILE",
  ENC_OTHER: "ENCRYPTED_OTHER_FILE",
  ENV: "ENV_FILE",
  OTHER: "OTHER_FILE",
};

function isEqualStr(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  return a.localeCompare(b) === 0;
}

function detectFileType(filename) {
  const f = filename.trim();
  if (f.endsWith(ENC_ENV_EXT)) {
    return FILE_TYPE.ENC_ENV;
  }
  if (f.endsWith(ENC_OTHER_EXT)) {
    return FILE_TYPE.ENC_OTHER;
  }
  if (/.(env|env.*)$/g.test(f)) {
    return FILE_TYPE.ENV;
  }
  return FILE_TYPE.OTHER;
}

function getDestFile(fileWithType) {
  switch (file.type) {
    case FILE_TYPE.ENC_ENV:
      return {
        file: fileWithType.file.slice(0, -ENC_ENV_EXT.length),
        type: FILE_TYPE.ENV,
      };
    case FILE_TYPE.ENC_OTHER:
      return {
        file: fileWithType.file.slice(0, -ENC_OTHER_EXT.length),
        type: FILE_TYPE.OTHER,
      };
    case FILE_TYPE.ENV:
      return {
        file: `${fileWithType.file}${ENC_ENV_EXT}`,
        type: FILE_TYPE.ENC_ENV,
      };
    case FILE_TYPE.OTHER:
      return {
        file: `${fileWithType.file}${ENC_OTHER_EXT}`,
        type: FILE_TYPE.ENC_OTHER,
      };
  }
  throw new Error(
    `Unsupported file type: ${fileWithType.type}: ${fileWithType.file}`
  );
}

function printTitle() {
  console.log(chalk`
🕵️  {bold.green Undercover}: {visible Store your environment variables and secrets in git safely.}`);
}

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

export function encryptOnlyIfChanged(text, previouslyEncrypted, key) {
  if (!previouslyEncrypted) {
    return encrypt(text, key);
  }
  const previousText = decrypt(previouslyEncrypted, key);
  if (isEqualStr(text, previousText)) {
    return previouslyEncrypted;
  } else {
    return encrypt(text, key);
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

async function encryptDotEnvFile(src, dest, secretKey) {
  console.log(
    chalk`{bold.green Encrypting values in} {magenta ${src}} -> ${dest}`
  );
  const content = await fs.readFile(src, { encoding: "utf-8" });
  const processEnvLine = (key, value) =>
    [key, encrypt(value, secretKey)].join("=");
  const encrypted = dotEnvFileTransformer(content, processEnvLine);
  await fs.writeFile(dest, encrypted);
}

async function decryptDotEnvFile(src, dest, secretKey) {
  console.log(
    chalk`{bold.green Decrypting values in} {magenta ${src}} -> ${dest}`
  );
  const content = await fs.readFile(src, { encoding: "utf-8" });
  const processEnvLine = (key, value) =>
    [key, decrypt(value, secretKey)].join("=");
  const decrypted = dotEnvFileTransformer(content, processEnvLine);
  await fs.writeFile(dest, decrypted);
}

async function encryptEntireFile(src, dest, secretKey) {
  console.log(chalk`{bold.green Encrypting file} {magenta ${src}} -> ${dest}`);
  const content = await fs.readFile(src, { encoding: "utf-8" });
  const encrypted = encrypt(content, secretKey);
  await fs.writeFile(dest, encrypted);
}

async function decryptEntireFile(src, dest, secretKey) {
  console.log(chalk`{bold.green Decrypting file} {magenta ${src}} -> ${dest}`);
  const content = await fs.readFile(src, { encoding: "utf-8" });
  const decrypted = decrypt(content, secretKey);
  await fs.writeFile(dest, decrypted);
}

async function getFiles(filesOrDirectories) {
  const results = [];
  try {
    for (const fileOrDir of filesOrDirectories) {
      const stat = await fs.stat(fileOrDir);
      if (stat.isFile()) {
        results.push(fileOrDir);
      } else if (stat.isDirectory()) {
        const filesInDir = await fs.readdir(fileOrDir);
        await Promise.all(
          filesInDir.map(async (f) => {
            const filePath = path.join(fileOrDir, f);
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
  return results.map((file) => ({
    file,
    type: detectFileType(file),
  }));
}

async function ask(q = "Question?", choices = []) {
  let ques = q + " ";
  const allChoices = choices.join("\n");
  if (allChoices) {
    ques = q + "\n" + allChoices + "\n> ";
  }
  const choice = await question(ques, { choices }).catch((e) => e);
  return choice;
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

async function encryptCommand(args) {
  const { options, positional: inputFiles } = processArgs(args);
  const filesWithType = await getFiles(inputFiles);

  let filesToEncrypt = filesWithType.filter((f) =>
    [FILE_TYPE.ENV, FILE_TYPE.OTHER].includes(f.type)
  );

  if (options["-f"] === "true") {
    filesToEncrypt = filesToEncrypt.map((f) => ({
      ...f,
      type: FILE_TYPE.OTHER,
    }));
  } else if (options["-e"] === "true") {
    filesToEncrypt = filesToEncrypt.map((f) => ({ ...f, type: FILE_TYPE.ENV }));
  }

  if (filesToEncrypt.length === 0) {
    return console.log(chalk`{red.bold No files found to encrypt}`);
  }

  const password = await ask(chalk`{bold Enter password}`);
  const secretKey = getSecretKey(password);

  for (const fileToEncrypt of filesToEncrypt) {
    const dest = getDestFile(fileToEncrypt);
    switch (fileToEncrypt.type) {
      case FILE_TYPE.ENV: {
        await encryptDotEnvFile(fileToEncrypt.file, dest.file, secretKey);
        break;
      }
      case FILE_TYPE.OTHER: {
        await encryptEntireFile(fileToEncrypt.file, dest.file, secretKey);
        break;
      }
    }
  }

  console.log(chalk`{green.bold All files encrypted successfully} 🔐`);
}

async function decryptCommand(args) {
  const { options, positional: inputFiles } = processArgs(args);
  const filesWithType = await getFiles(inputFiles);

  let filesToDecrypt = filesWithType.filter((f) =>
    [FILE_TYPE.ENC_OTHER, FILE_TYPE.ENC_ENV].includes(f.type)
  );

  if (filesToDecrypt.length === 0) {
    return console.log(chalk`{red.bold No files to decrypt}`);
  }

  const password = await ask(chalk`{bold Enter password}`);
  const secretKey = getSecretKey(password);

  for (const fileToDecrypt of filesToDecrypt) {
    const dest = getDestFile(fileToEncrypt);
    switch (fileToDecrypt.type) {
      case FILE_TYPE.ENC_ENV: {
        await decryptDotEnvFile(fileToDecrypt.file, dest.file, secretKey);
        break;
      }
      case FILE_TYPE.ENC_OTHER: {
        await decryptEntireFile(fileToDecrypt.file, dest.file, secretKey);
        break;
      }
    }
  }

  console.log(chalk`{green.bold All files decrypted successfully} 🔐`);
}

async function showDiff(encFile, secretKey) {
  const unencrypted = getDestFile(encFile);
  console.log(
    chalk`{bold diff between: ${encFile.file} and ${unencrypted.file}}`
  );
  const output = await $`git --no-pager diff --color $(cat ./env/abc222.env | git hash-object -w --stdin) $(cat ./env/abc2.env | git hash-object -w --stdin)`;
  console.log(output.stderr);
  console.log(output.stdout);
}

async function diffCommand(args) {
  $.verbose = false;
  const { options, positional: inputFiles } = processArgs(args);
  const filesWithType = await getFiles(inputFiles);

  for (const file of filesWithType) {
    //TODO:
  }

  $.verbose = true;
}

async function updateCommand() {
  const answer = await ask(
    chalk`{bold This will update undercover to latest version. Continue?}`,
    [chalk`{green yes}`, chalk`{red no}`]
  );
  if (!answer.toLowerCase().trim().startsWith("y")) {
    return;
  }
  const UPDATE_URL =
    "https://raw.githubusercontent.com/a7ul/undercover/main/undercover.mjs";
  const currentFile = import.meta.url.replace("file://", "");
  const resp = await fetch(UPDATE_URL);
  if (resp.ok) {
    const script = await resp.text();
    await fs.writeFile(currentFile, script, { encoding: "utf8", flag: "w" });
    chalk.green("Updated successfully! 🚀");
  } else {
    console.error(chalk`{red.bold Failed to update!}`, await resp.text());
    process.exit(-1);
  }
}

function helpCommand() {
  printTitle();
  console.log(chalk`
{bold.underline Usage:} {bold ./undercover.mjs} {magenta <command> [options]} <file...> | <dir...>

{bold.underline Command:}

{bold.magenta encrypt:} {bold ./undercover.mjs} {magenta encrypt [-f | -e]} <file...> | <dir...>
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
 
{bold.magenta decrypt:} {bold ./undercover.mjs} {magenta decrypt} <file.crypt...> | <file.ecrypt...> | <dir...>
{visible
  Decrypts the file using the secret provided in the prompt.
  For any other file encrypts the entire file. Useful for things like service accounts, ssh keys etc.
}
  <dir>  {visible decrypt all files in this directory.}

{bold.magenta update:} {bold ./undercover.mjs} {magenta update}
{visible
  Update this script to latest available version.
}  

{bold.magenta help:} {bold ./undercover.mjs} {magenta help}
{visible
  Show this help text.
}`);
}

function unknownCommand(command) {
  printTitle();
  console.error(
    chalk`\n{bold.red Error:} {red ${
      command ? `Unknown command: ${command}!` : `No command specified!`
    }}\n`
  );
  console.error(chalk`For help: {bold ./undercover.mjs} {bold.magenta help}`);
  process.exit(-1);
}

async function main() {
  const [command, ...args] = process.argv.slice(3);

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
