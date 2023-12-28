import {
	IAgentOptions,
	IDIDManager,
	IKeyManager,
	IResolver,
	TAgent,
} from '@veramo/core-types';
import { createAgent } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { Resolver } from 'did-resolver';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { KeyManagementSystem } from '@veramo/kms-local';
import { KeyDIDProvider, getDidKeyResolver } from '@veramo/did-provider-key';
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
import { CredentialSDJwt } from '../src/agent/CredentialSDJwt';
import { ICredentialSDJwt } from '../src/types/ICredentialSDJwt';

export const faucet = {
	prefix: 'cheqd',
	minimalDenom: 'ncheq',
	mnemonic:
		'sketch mountain erode window enact net enrich smoke claim kangaroo another visual write meat latin bacon pulp similar forum guilt father state erase bright',
	address: 'cheqd1rnr5jrt4exl0samwj0yegv99jeskl0hsxmcz96',
};

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
					'did:key': new KeyDIDProvider({
						defaultKms: 'local',
					}),
				},
				defaultProvider: 'did:cheqd:testnet',
			}),
			new DIDResolverPlugin({
				resolver: new Resolver({
					...getDidCheqdResolver(),
					...getDidKeyResolver(),
				}),
			}),
            new Cheqd({
                providers: [didProviderCheqdTestnet]
            }),
			new CredentialSDJwt(),
		],
	};

    // @ts-ignore
	return createAgent<T>(options || defaultOptions);
}
