# 🕵️ Undercover

> ⚠️ This project is now deprecated. Please take a look at https://github.com/a7ul/secrets.mjs

Store your environment variables and secrets in git safely.

This script is a single file pure nodejs script.

## Quick use (no install)

```
npx zx https://raw.githubusercontent.com/a7ul/undercover/main/undercover.mjs help
```

## Installation

You can use undercover by just copying it and commiting it in your repo.

```
curl https://raw.githubusercontent.com/a7ul/undercover/main/undercover.mjs > undercover.mjs
node ./undercover.mjs
```

or manually

```
curl https://raw.githubusercontent.com/a7ul/undercover/main/undercover.mjs > undercover.mjs
chmod a+x ./undercover.mjs
./undercover.mjs
```

It is recommended you commit undercover.mjs with your repo, so its easier to run whenever you want to decrypt or encrypt secrets.

Further updates can be pulled by just doing:

```sh
./undercover.mjs update
```

## Features

**Encrypt/Decrypt Env files**

First class `.env` files support. Only the values are encrypted and keys are left in plain text.
This makes it easy to see changes in the git when changing something in the encrypted file.

```sh
 ./undercover.mjs encrypt ./test.env
```

![envfiles](https://user-images.githubusercontent.com/4029423/117862198-acdbfe00-b292-11eb-93fe-1d91e1cce561.jpg)

**Encrypt/Decrypt entire files**

Useful for things like service accounts, ssh keys or any other file that is sensitive.

```sh
 ./undercover.mjs encrypt ./secret.json
```

![entirefile](https://user-images.githubusercontent.com/4029423/117862994-8f5b6400-b293-11eb-9b31-5d7676814c9e.png)

**Diff against encrypted file**

Displays the diff between the encrypted file and the decrypted file.

```sh
./undercover.mjs diff ./test.env.ecrypt
```

![diff](https://user-images.githubusercontent.com/4029423/117863116-b74ac780-b293-11eb-96fc-efba1b0a4b7a.png)

## Requirements

- Node v14 and above

## Development

- Run tests: `NODE_ENV=test node ./tests/run.mjs`

## References

- https://github.com/motdotla/dotenv/blob/master/lib/main.js
- http://vancelucas.com/blog/stronger-encryption-and-decryption-in-node-js/
- https://github.com/google/zx
- https://www.sohamkamani.com/blog/javascript/making-a-node-js-test-runner/
