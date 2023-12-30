import { AsyncJWTCryptoProvider, JWTVerificationResult, JSONObject } from '@eengineer1/sd-jwt-ts-node';
import {
	CreateCredentialOptions,
	CredentialPayload,
	VerifyCredentialOptions,
	createVerifiableCredentialJwt,
	verifyCredential as verifyCredentialJwt,
} from 'did-jwt-vc';
import { Resolvable } from 'did-resolver';
import { canonicalize } from 'json-canonicalize';

/**
 * Options for the VeramoCompactAsyncJWTCryptoProvider, sign method(s).
 *
 * @beta
 */
export type VeramoCompactAsyncJWTCryptoProviderSignOptions = {
	did: string;
	signer: (data: string | Uint8Array) => Promise<string>;
	alg: string;
	createCredentialOptions?: CreateCredentialOptions;
};

/**
 * Options for the VeramoCompactAsyncJWTCryptoProvider, verify method(s).
 *
 * @beta
 */
export type VeramoCompactAsyncJWTCryptoProviderVerifyOptions = {
	resolver: Resolvable;
	normalisedPayload?: CredentialPayload;
	verifyCredentialOptions?: VerifyCredentialOptions;
};

/**
 * The underlying library specific (sd-jwt-ts) Veramo Compact Async JWT Crypto Provider implementation.
 *
 * @beta
 */
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
			// verify + define verification result
			const { verifiableCredential, verified } = await verifyCredentialJwt(
				jwt,
				options.resolver,
				options?.verifyCredentialOptions
			);

			// validate verification result, negative should never happen as an error is thrown by convention
			if (!verified)
				return {
					verified: false,
					message: 'invalid_credential: Could not verify credential',
				} satisfies JWTVerificationResult;

			// validate normalised payload, if applicable + return verification result
			return options.normalisedPayload && options.normalisedPayload.proof.type === 'JwtProof2020'
				? (function () {
						// evaluate normalised payload against verifiable credential, other than jwt itself
						const untamperedWith =
							canonicalize({
								...verifiableCredential,
								proof: { ...verifiableCredential.proof, jwt: undefined },
							}) ===
							canonicalize({
								...options.normalisedPayload,
								proof: { ...options.normalisedPayload.proof, jwt: undefined },
							});

						// return verification result
						return {
							verified: untamperedWith,
							message: untamperedWith
								? undefined
								: 'invalid_credential: Credential JSON does not match JWT payload',
						} satisfies JWTVerificationResult;
					})()
				: ({
						verified,
					} satisfies JWTVerificationResult);
		} catch (error) {
			// return verification result
			return {
				verified: false,
				message: (error as Error).message || (error as Record<string, unknown>).toString(),
			} satisfies JWTVerificationResult;
		}
	}
}
