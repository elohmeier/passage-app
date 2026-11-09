---
title: Support
permalink: /support/
---

# Passage — Support

Passage is an iOS app for [passage](https://github.com/FiloSottile/passage) password stores, encrypted with [age](https://age-encryption.org).

## Getting started

1. **Try it:** on the welcome screen, choose *Try Demo Store**.
2. **Use your store:** connect a GitHub repository, clone any git repository (HTTPS or SSH), or open a folder in the Files app.
3. **Make it readable here:** Passage creates a key for this device in the Secure Enclave. Tap *Add This Device as Recipient*, then re-encrypt on your computer:

   ```
   cd ~/.passage/store && git pull && passage reencrypt && git push
   ```

4. **Start fresh:** connect an empty repository and choose *Set Up This Store*. Keep the recovery key it shows; it's the only way back in if you lose this device.

## AutoFill

Settings ▸ General ▸ AutoFill & Passwords ▸ enable Passage. Passwords, one-time codes and passkeys are offered in Safari and apps.

## Common questions

- **"This device isn't a recipient yet"**: entries are only readable on devices they're encrypted to. See step 3.
- **Recipients changed**: someone (or another of your devices) changed `.age-recipients`. Approve it only if you recognize the new recipients.
- **Post-quantum keys** need age 1.3 or later on your other devices.

## Contact

Open an issue at <https://github.com/elohmeier/passage-app/issues>. Please never include passwords, keys or other secrets in an issue.
