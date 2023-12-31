
# Veramo SD-JWT Plugin

This repository contains a plugin for the [Veramo](https://github.com/decentralized-identity/veramo) verifiable data framework that leverages the following specification compliant [SD-JWT (Selective Disclosure JSON Web Token) library](https://github.com/Eengineer1/sd-jwt-ts).

[![Apache 2.0 License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](https://choosealicense.com/licenses/mit/)

> ⚠️ This plugin is strictly an ESM module and requires Node.js >= 18.17.0.

## Overview

The Veramo SD-JWT plugin allows for privacy-preserving data sharing by enabling selective disclosure of data fields in a JWT credential payload. This is achieved by using the SD-JWT aforementioned library, which allows each field in the JWT payload to be individually disclosed.

## Installation

To install the Veramo SD-JWT plugin, use the following command:

```bash
npm install @eengineer1/veramo-credential-sd-jwt
```

## Usage

After installation, you can use the plugin in your Veramo agent as follows:

```typescript
import { createAgent, ... } from '@veramo/core'
import { CredentialSDJwt } from '@eengineer1/veramo-credential-sd-jwt'

const agent = new Agent({
    plugins: [
        ..., // other required plugins
        new CredentialSDJwt()
    ]
})
```

With the agent instantiated, you can now use the plugin to issue and / or verify SD-JWT credentials and presentations as follows:

```typescript
import { type CredentialPayload } from '@veramo/core-types'
import { type JSONObject } from '@eengineer1/sd-jwt-ts-node'

// original claimset
const claimset = {
    id: '7aea4ed3-9b02-4f64-8f05-aeb59899c8a2',
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: 'did:cheqd:testnet:09b20561-7339-40ea-a377-05ea35a0e82a',
    credentialSubject: {
        id: 'did:jwk:eyJhbGciOiJFUzI1NksiLCJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsInVzZSI6InNpZyIsIngiOiJmMmF2aHdTcTlNVGg4c0x0ZnBDZU1udnllSzdzVjIyRUtNZ2IzS1hOWXJZIiwieSI6ImFUUEY0OFZ5d0tKOFpJeEYzU0NweEtkNUhPeUt2cUZPWUcxQWc2Sm1qeVEifQ',
        nestedSimple: 'information',
        nestedObject: {
            nested: 'information',
        },
        nestedArray: ['information1', 'information2'],
    },
}

// non-selectively disclosable claimset
const undisclosedClaimset = {
    '@context': claimset['@context'],
    type: claimset.type,
    issuanceDate: 'anything-truthy',
    credentialSubject: {
        id: claimset.credentialSubject.id,
        nestedSimple: claimset.credentialSubject.nestedSimple,
    },
} satisfies JSONObject

// create + sign SD-JWT credential
const { sdJwt, normalisedCredential } = await agent.createVerifiableCredentialSDJwt({
    credential: claimset,
    undisclosedFields: undisclosedClaimset,
    removeOriginalFields: true,
    returnNormalisedCredential: true,
})

// verify SD-JWT credential
const { verified, message } = await agent.verifyVerifiableCredentialSDJwt({
    credential: sdJwt.jwt,
})

// create + sign SD-JWT presentation
const { sdJwtPresentation, normalisedPresentation } = await agent.createVerifiablePresentationSDJwt({
    presentation: {
    verifiableCredential: [sdJwt.jwt],
        holder: holder.didDocument.id,
    },
    removeOriginalFields: true,
    returnNormalisedPresentation: true,
})

// verify SD-JWT presentation
const { verified, message } = await agent.verifyVerifiablePresentationSDJwt({
    presentation: sdJwtPresentation,
})
```

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](./LICENSE) file for details.
