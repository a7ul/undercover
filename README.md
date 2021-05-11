# 🕵️ Undercover:

Store your environment variables and secrets in git safely.

# Quick use (no install)

```
npx zx https://raw.githubusercontent.com/a7ul/undercover/main/undercover.mjs help
```

# Installation

You can use undercover without installing.

```
curl https://raw.githubusercontent.com/a7ul/undercover/main/undercover.mjs > undercover.mjs
npx zx ./undercover.mjs
```

or

```
npm install -g zx
curl https://raw.githubusercontent.com/a7ul/undercover/main/undercover.mjs > undercover.mjs
chmod a+x ./undercover.mjs
./undercover.mjs
```

# Development

Run tests: `NODE_ENV=test zx ./tests/run.mjs`

## References

- https://github.com/motdotla/dotenv/blob/master/lib/main.js
- http://vancelucas.com/blog/stronger-encryption-and-decryption-in-node-js/
- https://github.com/google/zx
- https://www.sohamkamani.com/blog/javascript/making-a-node-js-test-runner/
