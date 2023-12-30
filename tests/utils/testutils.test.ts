import {
	CredentialPayload,
	IAgentOptions,
	IDIDManager,
	IKeyManager,
	IResolver,
	MinimalImportableIdentifier,
	TAgent,
} from '@veramo/core-types';
import { createAgent } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { DIDDocument, Resolver } from 'did-resolver';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { KeyManagementSystem } from '@veramo/kms-local';
import { JwkDIDProvider, getDidJwkResolver } from '@veramo/did-provider-jwk';
import {
	CheqdDIDProvider,
	getResolver as getDidCheqdResolver,
	DefaultRPCUrls,
	LitCompatibleCosmosChains,
	LitNetworks,
	ICheqd,
	Cheqd,
} from '@cheqd/did-provider-cheqd';
import { CheqdNetwork } from '@cheqd/sdk';
import { CredentialSDJwt } from '../../src/agent/CredentialSDJwt';
import { ICredentialSDJwt } from '../../src/types/ICredentialSDJwt';
import dotenv from 'dotenv';

export const faucet = {
	prefix: 'cheqd',
	minimalDenom: 'ncheq',
	mnemonic:
		'sketch mountain erode window enact net enrich smoke claim kangaroo another visual write meat latin bacon pulp similar forum guilt father state erase bright',
	address: 'cheqd1rnr5jrt4exl0samwj0yegv99jeskl0hsxmcz96',
};

export const unsignedCredential = {
	id: '7aea4ed3-9b02-4f64-8f05-aeb59899c8a2',
	'@context': ['https://www.w3.org/2018/credentials/v1'],
	type: ['VerifiableCredential'],
	issuer: '',
	credentialSubject: {
		id: '',
		nestedSimple: 'information',
		nestedObject: {
			nested: 'information',
		},
		nestedArray: ['information1', 'information2'],
	},
} satisfies CredentialPayload;

export function createLocalAgent<T extends TAgent<IDIDManager & IKeyManager & IResolver & ICheqd & ICredentialSDJwt>>(
	options?: IAgentOptions
): T {
	const didProviderCheqdTestnet = new CheqdDIDProvider({
		defaultKms: 'local',
		cosmosPayerSeed: faucet.mnemonic,
		networkType: CheqdNetwork.Testnet,
		rpcUrl: DefaultRPCUrls.testnet,
		dkgOptions: {
			chain: LitCompatibleCosmosChains.cheqdTestnet,
			network: LitNetworks.serrano,
		},
	});
	const defaultOptions = {
		plugins: [
			new KeyManager({
				store: new MemoryKeyStore(),
				kms: {
					local: new KeyManagementSystem(new MemoryPrivateKeyStore()),
				},
			}),
			new DIDManager({
				store: new MemoryDIDStore(),
				providers: {
					'did:cheqd:testnet': didProviderCheqdTestnet,
					'did:jwk': new JwkDIDProvider({
						defaultKms: 'local',
					}),
				},
				defaultProvider: 'did:cheqd:testnet',
			}),
			new DIDResolverPlugin({
				resolver: new Resolver({
					...getDidCheqdResolver(),
					...getDidJwkResolver(),
				}),
			}),
			new Cheqd({
				providers: [didProviderCheqdTestnet],
			}),
			new CredentialSDJwt(),
		],
	};

	// @ts-ignore
	return createAgent<T>(options || defaultOptions);
}

export async function bootstrapLocalAgent<
	T extends TAgent<IDIDManager & IKeyManager & IResolver & ICheqd & ICredentialSDJwt>,
>(agent: T): Promise<{ agent: T; issuer: VerifiedEntity; holder: VerifiedEntity }> {
	// load environment variables
	dotenv.config();

	// define issuer
	const issuer = {
		didDocument: {
			id: 'did:cheqd:testnet:09b20561-7339-40ea-a377-05ea35a0e82a',
			controller: ['did:cheqd:testnet:09b20561-7339-40ea-a377-05ea35a0e82a'],
			verificationMethod: [
				{
					id: 'did:cheqd:testnet:09b20561-7339-40ea-a377-05ea35a0e82a#key-1',
					type: 'Ed25519VerificationKey2018',
					controller: 'did:cheqd:testnet:09b20561-7339-40ea-a377-05ea35a0e82a',
					publicKeyBase58: '8qPDxGgPHLjUFEX1qneY3zR1MysJtV3KWL2evxDnsh7Y',
				},
			],
			authentication: ['did:cheqd:testnet:09b20561-7339-40ea-a377-05ea35a0e82a#key-1'],
			assertionMethod: ['did:cheqd:testnet:09b20561-7339-40ea-a377-05ea35a0e82a#key-1'],
		} satisfies DIDDocument,
		minimalImportableIdentifier: {
			did: 'did:cheqd:testnet:09b20561-7339-40ea-a377-05ea35a0e82a',
			alias: 'issuer',
			provider: 'did:cheqd:testnet',
			controllerKeyId: '7466d0b883567fafea41047080a5d90f81604a06214957306fc2846f3a31b17b',
			keys: [
				{
					publicKeyHex: '7466d0b883567fafea41047080a5d90f81604a06214957306fc2846f3a31b17b',
					privateKeyHex: process.env.ISSUER_PRIVATE_KEY_HEX as string,
					kid: '7466d0b883567fafea41047080a5d90f81604a06214957306fc2846f3a31b17b',
					type: 'Ed25519',
					kms: 'local',
				},
			],
		} satisfies MinimalImportableIdentifier,
	};

	// load issuer identifier + keys
	await agent.didManagerImport({
		...issuer.minimalImportableIdentifier,
	});

	// define holder
	const holder = {
		didDocument: {
			'@context': [
				'https://www.w3.org/ns/did/v1',
				{
					'@vocab': 'https://www.iana.org/assignments/jose#',
				},
			],
			id: 'did:jwk:eyJhbGciOiJFUzI1NksiLCJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsInVzZSI6InNpZyIsIngiOiJmMmF2aHdTcTlNVGg4c0x0ZnBDZU1udnllSzdzVjIyRUtNZ2IzS1hOWXJZIiwieSI6ImFUUEY0OFZ5d0tKOFpJeEYzU0NweEtkNUhPeUt2cUZPWUcxQWc2Sm1qeVEifQ',
			verificationMethod: [
				{
					id: '#0',
					type: 'JsonWebKey2020',
					controller:
						'did:jwk:eyJhbGciOiJFUzI1NksiLCJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsInVzZSI6InNpZyIsIngiOiJmMmF2aHdTcTlNVGg4c0x0ZnBDZU1udnllSzdzVjIyRUtNZ2IzS1hOWXJZIiwieSI6ImFUUEY0OFZ5d0tKOFpJeEYzU0NweEtkNUhPeUt2cUZPWUcxQWc2Sm1qeVEifQ',
					publicKeyJwk: {
						alg: 'ES256K',
						crv: 'secp256k1',
						kty: 'EC',
						use: 'sig',
						x: 'f2avhwSq9MTh8sLtfpCeMnvyeK7sV22EKMgb3KXNYrY',
						y: 'aTPF48VywKJ8ZIxF3SCpxKd5HOyKvqFOYG1Ag6JmjyQ',
					},
				},
			],
			authentication: ['#0'],
			assertionMethod: ['#0'],
			capabilityInvocation: ['#0'],
			capabilityDelegation: ['#0'],
		},
		minimalImportableIdentifier: {
			did: 'did:jwk:eyJhbGciOiJFUzI1NksiLCJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsInVzZSI6InNpZyIsIngiOiJmMmF2aHdTcTlNVGg4c0x0ZnBDZU1udnllSzdzVjIyRUtNZ2IzS1hOWXJZIiwieSI6ImFUUEY0OFZ5d0tKOFpJeEYzU0NweEtkNUhPeUt2cUZPWUcxQWc2Sm1qeVEifQ',
			alias: 'holder',
			provider: 'did:jwk',
			controllerKeyId:
				'047f66af8704aaf4c4e1f2c2ed7e909e327bf278aeec576d8428c81bdca5cd62b66933c5e3c572c0a27c648c45dd20a9c4a7791cec8abea14e606d4083a2668f24',
			keys: [
				{
					publicKeyHex:
						'047f66af8704aaf4c4e1f2c2ed7e909e327bf278aeec576d8428c81bdca5cd62b66933c5e3c572c0a27c648c45dd20a9c4a7791cec8abea14e606d4083a2668f24',
					privateKeyHex: process.env.HOLDER_PRIVATE_KEY_HEX as string,
					kid: '047f66af8704aaf4c4e1f2c2ed7e909e327bf278aeec576d8428c81bdca5cd62b66933c5e3c572c0a27c648c45dd20a9c4a7791cec8abea14e606d4083a2668f24',
					type: 'Secp256k1',
					kms: 'local',
				},
			],
		},
	} as VerifiedEntity;

	// load holder identifier + keys
	await agent.didManagerImport({
		...holder.minimalImportableIdentifier,
	});

	// redact private keys - case: issuer
	issuer.minimalImportableIdentifier.keys = issuer.minimalImportableIdentifier.keys.map((key) => {
		return {
			...key,
			privateKeyHex: '',
		};
	});

	// redact private keys - case: holder
	holder.minimalImportableIdentifier.keys = holder.minimalImportableIdentifier.keys.map((key) => {
		return {
			...key,
			privateKeyHex: '',
		};
	});

	// return
	return {
		agent,
		issuer,
		holder,
	};
}

export type VerifiedEntity = {
	didDocument: DIDDocument;
	minimalImportableIdentifier: MinimalImportableIdentifier;
};
