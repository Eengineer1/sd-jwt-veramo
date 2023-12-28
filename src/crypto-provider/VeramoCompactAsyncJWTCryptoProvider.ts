import { AsyncJWTCryptoProvider, JWTVerificationResult, JSONObject } from '@eengineer1/sd-jwt-ts-node';
import {
	CreateCredentialOptions,
	CredentialPayload,
	VerifyCredentialOptions,
	createVerifiableCredentialJwt,
	verifyCredential as verifyCredentialJwt,
} from 'did-jwt-vc';
import { Resolvable } from 'did-resolver';

export type VeramoCompactAsyncJWTCryptoProviderSignOptions = {
	did: string;
	signer: (data: string | Uint8Array) => Promise<string>;
	alg: string;
	createCredentialOptions?: CreateCredentialOptions;
};

export type VeramoCompactAsyncJWTCryptoProviderVerifyOptions = {
	resolver: Resolvable;
	verifyCredentialOptions?: VerifyCredentialOptions;
};

export class VeramoCompactAsyncJWTCryptoProvider implements AsyncJWTCryptoProvider {
	constructor() {}

	async signAsync(
		payload: JSONObject,
		keyId?: string | null | undefined,
		options?: VeramoCompactAsyncJWTCryptoProviderSignOptions
	): Promise<string> {
		// validate options
		if (!options) {
			throw new Error('invalid_argument: options must be provided');
		}

		// validate options - case: did
		if (!options.did) {
			throw new Error('invalid_argument: options.did must be provided');
		}

		// validate options - case: signer
		if (!options.signer) {
			throw new Error('invalid_argument: options.signer must be provided');
		}

		// validate options - case: alg
		if (!options.alg) {
			throw new Error('invalid_argument: options.alg must be provided');
		}

		// sign + return
		return await createVerifiableCredentialJwt(
			payload as CredentialPayload,
			{
				did: options.did,
				signer: options.signer,
				alg: options.alg,
			},
			options?.createCredentialOptions
		);
	}

	async verifyAsync(
		jwt: string,
		options?: VeramoCompactAsyncJWTCryptoProviderVerifyOptions
	): Promise<JWTVerificationResult> {
		// validate options
		if (!options) {
			throw new Error('invalid_argument: options must be provided');
		}

		// verify jwt
		try {
			// verify
			await verifyCredentialJwt(jwt, options.resolver, options?.verifyCredentialOptions);

			// return verification result
			return {
				verified: true,
			} satisfies JWTVerificationResult;
		} catch (error) {
			// return verification result
			return {
				verified: false,
				message: (error as Error).message || (error as Record<string, unknown>).toString(),
			} satisfies JWTVerificationResult;
		}
	}
}
