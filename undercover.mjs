#!/usr/bin/env zx

import crypto from "crypto";
import path from "path";

const ENCRYPTION_DELIMITER = ".";
const ENC_DOT_ENV_EXT = ".ecrypt";
const ENC_OTHER_EXT = ".crypt";

function printTitle() {
  console.log(chalk`
🕵️  {bold.green Undercover}: {visible Store your environment variables and secrets in git safely.}`);
}

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

async function encryptDotEnvFile(src, secretKey) {
  const dest = `${src}${ENC_DOT_ENV_EXT}`;
  console.log(
    chalk`{bold.green Encrypting values in} {magenta ${src}} -> ${dest}`
  );
  const content = await fs.readFile(src, { encoding: "utf-8" });
  const onValue = (value) => encrypt(value, secretKey);
  const encrypted = dotEnvFileTransformer(content, onValue);
  await fs.writeFile(dest, encrypted);
}

async function decryptDotEnvFile(file, secretKey) {
  const content = await fs.readFile(file, { encoding: "utf-8" });
  const processEnvLine = (key, value) =>
    [key, decrypt(value, secretKey)].join("=");
  return dotEnvFileTransformer(content, processEnvLine);
}

async function encryptEntireFile(src, secretKey) {
  const dest = `${src}${ENC_OTHER_EXT}`;
  console.log(chalk`{bold.green Encrypting file} {magenta ${src}} -> ${dest}`);
  const content = await fs.readFile(src, { encoding: "utf-8" });
  const encrypted = encrypt(content, secretKey);
  await fs.writeFile(dest, encrypted);
}

async function decryptEntireFile(file, secretKey) {
  const content = await fs.readFile(file, { encoding: "utf-8" });
  return decrypt(content, secretKey);
}

function detectFileType(filename) {
  const f = filename.trim();
  if (f.endsWith(ENC_DOT_ENV_EXT)) {
    return "ENCRYPTED_ENV_FILE";
  }
  if (f.endsWith(ENC_OTHER_EXT)) {
    return "ENCRYPTED_OTHER_FILE";
  }
  if (/.(env|env.*)$/g.test(f)) {
    return "ENV_FILE";
  }
  return "OTHER_FILE";
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
  } finally {
    return results;
  }
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
  const files = await getFiles(inputFiles);

  const filesWithType = files.map((file) => ({
    file,
    type: detectFileType(file),
  }));

  let filesToEncrypt = filesWithType.filter((f) =>
    ["ENV_FILE", "OTHER_FILE"].includes(f.type)
  );

  if (options["-f"] === "true") {
    filesToEncrypt = filesToEncrypt.map((f) => ({ ...f, type: "OTHER_FILE" }));
  } else if (options["-e"] === "true") {
    filesToEncrypt = filesToEncrypt.map((f) => ({ ...f, type: "ENV_FILE" }));
  }

  if (filesToEncrypt.length === 0) {
    return console.log(chalk`{red.bold No files found to encrypt}`);
  }

  const password = await ask(chalk`{bold Enter password}`);
  const secretKey = getSecretKey(password);

  for (const fileToEncrypt of filesToEncrypt) {
    switch (fileToEncrypt.type) {
      case "ENV_FILE": {
        await encryptDotEnvFile(fileToEncrypt.file, secretKey);
        break;
      }
      case "OTHER_FILE": {
        await encryptEntireFile(fileToEncrypt.file, secretKey);
        break;
      }
    }
  }

  console.log(chalk`{green.bold All files encrypted successfully} 🔐`);
}

async function decryptCommand(args) {
  const { options, positional: inputFiles } = processArgs(args);
  const files = await getFiles(inputFiles);

  const filesWithType = files.map((file) => ({
    file,
    type: detectFileType(file),
  }));

  let filesToDecrypt = filesWithType.filter((f) =>
    ["ENCRYPTED_OTHER_FILE", "ENCRYPTED_ENV_FILE"].includes(f.type)
  );

  if (filesToDecrypt.length === 0) {
    return console.log(chalk`{red.bold No files to decrypt}`);
  }

  const password = await ask(chalk`{bold Enter password}`);
  const secretKey = getSecretKey(password);

  for (const fileToDecrypt of filesToDecrypt) {
    switch (fileToDecrypt.type) {
      case "ENCRYPTED_ENV_FILE": {
        console.log(
          chalk`{bold.green Decrypting values in ${fileToDecrypt.file}}`
        );
        await decryptDotEnvFile(fileToDecrypt.file, secretKey);
        break;
      }
      case "ENCRYPTED_OTHER_FILE": {
        console.log(chalk`{bold.green Decrypting file ${fileToDecrypt.file}}`);
        await decryptEntireFile(fileToDecrypt.file, secretKey);
        break;
      }
    }
  }

  console.log(chalk`{green.bold All files decrypted successfully} 🔐`);
}

async function updateCommand() {
  const answer = await ask(
    chalk`{bold This will update this script to latest version. Continue?}`,
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

await main();
