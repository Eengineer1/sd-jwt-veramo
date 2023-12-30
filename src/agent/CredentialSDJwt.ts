import {
	IAgentPlugin,
	IError,
	IIdentifier,
	IKey,
	IKeyManagerSignArgs,
	VerifiableCredential,
	W3CVerifiableCredential,
	W3CVerifiablePresentation,
} from '@veramo/core-types';
import {
	extractIssuer,
	processEntryToArray,
	MANDATORY_CREDENTIAL_CONTEXT,
	isDefined,
	removeDIDParameters,
	asArray,
} from '@veramo/utils';
import {
	type ICredentialSDJwt,
	type IRequiredContext,
	type ICreateVerifiableCredentialSDJwtArgs,
	type TCreateVerifiableCredentialSDJwtResult,
	type TCreateVerifiablePresentationSDJwtResult,
	type ICreateVerifiablePresentationSDJwtArgs,
	type IVerifyVerifiableCredentialSDJwtArgs,
	type TVerifyVerifiableCredentialSDJwtResult,
	type AugmentedDocumentFormat,
	type IVerifyVerifiablePresentationSDJwtArgs,
	type TVerifyVerifiablePresentationSDJwtResult,
	AugmentedDocumentFormats,
} from '../types/ICredentialSDJwt.js';
import {
	VeramoCompactAsyncJWTCryptoProvider,
	VeramoCompactAsyncJWTCryptoProviderVerifyOptions,
} from '../crypto-provider/VeramoCompactAsyncJWTCryptoProvider.js';
import { SDJwt, SDPayload } from '@eengineer1/sd-jwt-ts-node';
import {
	createVerifiablePresentationJwt,
	normalizeCredential,
	normalizePresentation,
	verifyPresentation as verifyPresentationJwt,
	type PresentationPayload,
} from 'did-jwt-vc';
import { toString } from 'uint8arrays';
import { Resolvable } from 'did-resolver';
import { decodeJWT } from 'did-jwt';
import schema from '../plugin.schema.json' assert { type: 'json' };
import Debug from 'debug';

const debug = Debug('veramo:credential-sd-jwt:CredentialSDJwt');

/**
 * {@inheritDoc ICredentialSDJwt}
 * @beta
 */
export class CredentialSDJwt implements IAgentPlugin {
	readonly schema = schema.ICredentialSDJwt;
	readonly methods: ICredentialSDJwt;

	constructor() {
		this.methods = {
			createVerifiableCredentialSDJwt: this.createVerifiableCredentialSDJwt.bind(this),
			createVerifiablePresentationSDJwt: this.createVerifiablePresentationSDJwt.bind(this),
			verifyVerifiableCredentialSDJwt: this.verifyVerifiableCredentialSDJwt.bind(this),
			verifyVerifiablePresentationSDJwt: this.verifyVerifiablePresentationSDJwt.bind(this),
		};
	}

	/**
	 * {@inheritDoc ICredentialSDJwt.createVerifiableCredentialSDJwt}
	 */
	async createVerifiableCredentialSDJwt(
		args: ICreateVerifiableCredentialSDJwtArgs,
		context: IRequiredContext
	): Promise<TCreateVerifiableCredentialSDJwtResult> {
		// define credential context
		const credentialContext = processEntryToArray(args?.credential?.['@context'], MANDATORY_CREDENTIAL_CONTEXT);

		// define credential type
		const credentialType = processEntryToArray(args?.credential?.type, 'VerifiableCredential');

		// define issuance date
		const issuanceDate = new Date().toISOString();

		// validate expiration date
		if (args.credential.expirationDate) {
			// define expiration date
			const expirationDate =
				args.credential.expirationDate instanceof Date
					? args.credential.expirationDate
					: new Date(args.credential.expirationDate);

			// throw, if not applicable
			if (expirationDate < new Date(issuanceDate)) {
				throw new Error(
					'invalid_argument: credential.expirationDate must be in the future and greater than issuanceDate'
				);
			}
		}

		// define credential
		args.credential = {
			...args.credential,
			'@context': credentialContext,
			type: credentialType,
			issuanceDate,
		};

		// define issuer
		const issuer = extractIssuer(args.credential, { removeParameters: true });
		if (!issuer || typeof issuer === 'undefined') {
			throw new Error('invalid_argument: credential.issuer must not be empty');
		}

		// define identifier
		const identifier = await (async function () {
			try {
				return await context.agent.didManagerGet({ did: issuer });
			} catch (e) {
				throw new Error(`invalid_argument: credential.issuer must be a DID managed by this agent: ${e}`);
			}
		})();

		// define jwt crypto provider
		const jwtCryptoProvider = new VeramoCompactAsyncJWTCryptoProvider();

		// define sd payload
		const sdPayload = args.undisclosedFields
			? SDPayload.createSDPayloadFromFullAndUndisclosedPayload(args.credential, args.undisclosedFields)
			: await (async function () {
					// use sd map, if provided
					return args.sdMap
						? SDPayload.createSDPayload(args.credential, args.sdMap)
						: SDPayload.createSDPayloadFromFullAndUndisclosedPayload(args.credential, {});
				})();

		// sign credential
		try {
			// define signing key
			const key = CredentialSDJwt.pickSigningKey(identifier, args.keyRef);

			// define algorithm
			const algorithm = CredentialSDJwt.pickSigningAlgorithm(key);

			// sign + define instance
			const sdJwt = await SDJwt.signAsync(sdPayload, jwtCryptoProvider, undefined, undefined, {
				did: identifier.did,
				signer: async (data: string) => {
					return await context.agent.keyManagerSign({
						keyRef: key.kid,
						data,
						algorithm,
					} satisfies IKeyManagerSignArgs);
				},
				alg: algorithm,
			});

			// return
			return {
				sdJwt,
				normalisedCredential: args.returnNormalisedCredential ? normalizeCredential(sdJwt.jwt) : undefined,
			};
		} catch (error) {
			// track error trace
			debug(error);

			// throw error
			throw new Error(`invalid_credential: Could not sign credential: ${error}`);
		}
	}

	/**
	 * {@inheritDoc ICredentialSDJwt.createVerifiablePresentationSDJwt}
	 */
	async createVerifiablePresentationSDJwt(
		args: ICreateVerifiablePresentationSDJwtArgs,
		context: IRequiredContext
	): Promise<TCreateVerifiablePresentationSDJwtResult> {
		// define presentation context
		const presentationContext = processEntryToArray(args?.presentation?.['@context'], MANDATORY_CREDENTIAL_CONTEXT);

		// define presentation type
		const presentationType = processEntryToArray(args?.presentation?.type, 'VerifiablePresentation');

		// define issuance date
		const issuanceDate = new Date().toISOString();

		// validate expiration date
		if (args.presentation.expirationDate) {
			// define expiration date
			const expirationDate =
				args.presentation.expirationDate instanceof Date
					? args.presentation.expirationDate
					: new Date(args.presentation.expirationDate);

			// throw, if not applicable
			if (expirationDate < new Date(issuanceDate)) {
				throw new Error(
					'invalid_argument: presentation.expirationDate must be in the future and greater than issuanceDate'
				);
			}
		}

		// define presentation
		args.presentation = {
			...args.presentation,
			'@context': presentationContext,
			type: presentationType,
			issuanceDate,
		};

		// validate holder
		if (!isDefined(args.presentation.holder)) {
			throw new Error('invalid_argument: presentation.holder must be defined');
		}

		// define holder
		const holder = removeDIDParameters(args.presentation.holder);

		// define identifier
		const identifier = await (async function () {
			try {
				return await context.agent.didManagerGet({ did: holder });
			} catch (e) {
				throw new Error(`invalid_argument: presentation.holder must be a DID managed by this agent: ${e}`);
			}
		})();

		// transform credentials to canonical form, as JWTs, if applicable
		args.presentation.verifiableCredential = (args?.presentation?.verifiableCredential?.map((credential) => {
			return typeof credential !== 'string' && credential.proof.jwt ? credential.proof.jwt : credential;
		}) || []) as string[];

		// validate SD-JWT presentation transformations - case: presentWithSDMap
		if (
			args?.presentation?.presentWithSDMap &&
			args?.presentation?.presentWithSDMap?.length > 0 &&
			args?.presentation?.presentWithHolderJwt &&
			args?.presentation?.presentWithHolderJwt?.length > 0
		) {
			// throw, if presentWithSDMap is not an array
			if (!Array.isArray(args.presentation.presentWithSDMap)) {
				throw new Error('invalid_argument: presentation.presentWithSDMap must be an array');
			}

			// throw, if presentWithSDMap is not of the same length as verifiableCredential
			if (args.presentation.presentWithSDMap.length !== args.presentation.verifiableCredential.length) {
				throw new Error(
					'invalid_argument: presentation.presentWithSDMap must be of the same length as presentation.verifiableCredential'
				);
			}

			// throw, if presentWithHolderJwt is not of the same length as verifiableCredential
			if (args.presentation.presentWithHolderJwt.length !== args.presentation.verifiableCredential.length) {
				throw new Error(
					'invalid_argument: presentation.presentWithHolderJwt must be of the same length as presentation.verifiableCredential'
				);
			}

			// throw, if presentWithSDMap is not of the same length as presentWithHolderJwt or vice versa
			if (args.presentation.presentWithSDMap.length !== args.presentation.presentWithHolderJwt.length) {
				throw new Error(
					'invalid_argument: presentation.presentWithSDMap must be of the same length as presentation.presentWithHolderJwt'
				);
			}

			// apply further SD-JWT presentation transformations, if applicable
			args.presentation.verifiableCredential = args.presentation.verifiableCredential.map((credential, index) => {
				// early return, if no further transformations are applicable
				if (!args.presentation.presentWithSDMap![index] && !args.presentation.presentWithHolderJwt![index]) {
					return credential;
				}

				// otherwise, parse SD-JWT credential
				const sdJwt = SDJwt.parse(credential as string);

				// apply SD-JWT presentation transformations
				return sdJwt.present(
					args.presentation.presentWithSDMap![index],
					args.presentation.presentWithHolderJwt![index]
				).jwt;
			});
		}

		// define signing key
		const key = CredentialSDJwt.pickSigningKey(identifier, args.keyRef);

		// define algorithm
		const algorithm = CredentialSDJwt.pickSigningAlgorithm(key);

		// sign + define instance
		const sdJwtPresentation = await createVerifiablePresentationJwt(
			args.presentation as PresentationPayload,
			{
				did: identifier.did,
				signer: async (data: string | Uint8Array) => {
					return await context.agent.keyManagerSign({
						keyRef: key.kid,
						data: data instanceof Uint8Array ? toString(data, 'utf-8') : data,
						algorithm,
					} satisfies IKeyManagerSignArgs);
				},
				alg: algorithm,
			},
			{
				...args,
				removeOriginalFields:
					typeof args.removeOriginalFields === 'undefined' ? true : !!args.removeOriginalFields,
			}
		);

		// return
		return {
			sdJwtPresentation,
			normalisedPresentation: args.returnNormalisedPresentation
				? normalizePresentation(sdJwtPresentation)
				: undefined,
		};
	}

	/**
	 * {@inheritDoc ICredentialSDJwt.verifyVerifiableCredentialSDJwt}
	 */
	async verifyVerifiableCredentialSDJwt(
		args: IVerifyVerifiableCredentialSDJwtArgs,
		context: IRequiredContext
	): Promise<TVerifyVerifiableCredentialSDJwtResult> {
		// detect document type
		const documentType = CredentialSDJwt.detectDocumentType(args.credential);

		// validate document type
		if (documentType !== AugmentedDocumentFormats.sdjwt) {
			throw new Error('invalid_argument: Credential must be a SD-JWT');
		}

		// define SD-JWT credential
		const sdJwt =
			typeof args.credential === 'string' ? SDJwt.parse(args.credential) : SDJwt.parse(args.credential.proof.jwt);

		// define jwt crypto provider
		const jwtCryptoProvider = new VeramoCompactAsyncJWTCryptoProvider();

		// define resolvable
		const resolver = { resolve: (didUrl: string) => context.agent.resolveDid({ didUrl }) } satisfies Resolvable;

		// verify
		try {
			// define verification policies
			const verificationPolicies = {
				...args.policies,
				nbf: args?.policies?.nbf || args?.policies?.issuanceDate,
				iat: args?.policies?.iat || args?.policies?.issuanceDate,
				exp: args?.policies?.exp || args?.policies?.expirationDate,
				aud: args?.policies?.aud || args?.policies?.audience,
			};

			// verify + define verification result
			const { verified, message } = await sdJwt.verifyAsync(jwtCryptoProvider, {
				resolver,
				verifyCredentialOptions: { policies: verificationPolicies },
				normalisedPayload: normalizeCredential(sdJwt.jwt),
			} satisfies VeramoCompactAsyncJWTCryptoProviderVerifyOptions);

			// validate verification result, negative should never happen as an error is thrown by convention
			if (!verified)
				return {
					verified,
					message,
				} satisfies TVerifyVerifiableCredentialSDJwtResult;

			// return verification result
			return {
				verified: true,
			} satisfies TVerifyVerifiableCredentialSDJwtResult;
		} catch (error) {
			// track error trace
			debug(error);

			// return verification result
			return {
				verified: false,
				message: `invalid_credential: Could not verify credential: ${(error as Error).message || error}`,
			} satisfies TVerifyVerifiableCredentialSDJwtResult;
		}
	}

	/**
	 * {@inheritDoc ICredentialSDJwt.verifyVerifiablePresentationSDJwt}
	 */
	async verifyVerifiablePresentationSDJwt(
		args: IVerifyVerifiablePresentationSDJwtArgs,
		context: IRequiredContext
	): Promise<TVerifyVerifiablePresentationSDJwtResult> {
		// detect document type
		const documentType = CredentialSDJwt.detectDocumentType(args.presentation);

		// validate document type
		if (documentType !== AugmentedDocumentFormats.jwt && documentType !== AugmentedDocumentFormats.sdjwt) {
			throw new Error('invalid_argument: Presentation must be a JWT or SD-JWT containing SD-JWT credentials');
		}

		// define SD-JWT presentation
		const sdJwtPresentation =
			typeof args.presentation === 'string' ? args.presentation : args.presentation.proof.jwt;

		// define resolvable
		const resolver = { resolve: (didUrl: string) => context.agent.resolveDid({ didUrl }) } satisfies Resolvable;

		// define audience
		const audience = !args.domain
			? await (async function () {
					// define decoded payload
					const { payload } = decodeJWT(sdJwtPresentation);

					// define intended audience
					const intendedAudience = asArray(payload.aud);

					// define managed dids
					const managedDids = await context.agent.didManagerFind();

					// find managed dids matching audience + apply fallback
					return managedDids.filter((did) => intendedAudience.includes(did.did))?.shift()?.did;
				})()
			: args.domain;

		// define verification policies
		const verificationPolicies = {
			...args.policies,
			nbf: args?.policies?.nbf || args?.policies?.issuanceDate,
			iat: args?.policies?.iat || args?.policies?.issuanceDate,
			exp: args?.policies?.exp || args?.policies?.expirationDate,
			aud: args?.policies?.aud || args?.policies?.audience,
		};

		// verify presentation
		try {
			// verify + define verification result
			const { verified } = await verifyPresentationJwt(sdJwtPresentation, resolver, {
				...args,
				audience,
				policies: verificationPolicies,
			});

			// validate + return verification result, negative should never happen as an error is thrown by convention
			return {
				verified,
				message: !verified ? 'invalid_presentation: Could not verify presentation' : undefined,
			} satisfies TVerifyVerifiablePresentationSDJwtResult;
		} catch (error) {
			// track error trace
			debug(error);

			// return verification result
			return {
				verified: false,
				message: `invalid_presentation: Could not verify presentation: ${(error as Error).message || error}`,
			} satisfies TVerifyVerifiablePresentationSDJwtResult;
		}
	}

	private static pickSigningKey(identifier: IIdentifier, keyRef?: string): IKey {
		return !keyRef
			? (function () {
					const key = identifier.keys.find(
						(k) => k.type === 'Secp256k1' || k.type === 'Ed25519' || k.type === 'Secp256r1'
					);
					if (!key) throw Error(`key_not_found: No signing key for ${identifier.did}`);
					return key;
				})()
			: (function () {
					const key = identifier.keys.find((k) => k.kid === keyRef);
					if (!key) throw Error(`key_not_found: No signing key for ${identifier.did} with kid ${keyRef}`);
					return key;
				})();
	}

	private static pickSigningAlgorithm(key: IKey): string {
		switch (key.type) {
			case 'Ed25519':
				return 'EdDSA';
			case 'Secp256r1':
				return 'ES256';
			default:
				return 'ES256K';
		}
	}

	private static detectDocumentType(
		document: W3CVerifiableCredential | W3CVerifiablePresentation
	): AugmentedDocumentFormat {
		// validate document
		if (!document) throw new Error('invalid_argument: document must be provided');

		// validate document - case: arbitrary value
		if (typeof document !== 'string' && typeof document !== 'object')
			throw new Error('invalid_argument: document must be a VerifiableCredential or a VerifiablePresentation');

		// validate document - case: arbitrary object
		if (typeof document === 'object' && !document.proof)
			throw new Error('invalid_argument: document must be a VerifiableCredential or a VerifiablePresentation');

		// define if JWT
		const isJWT = typeof document === 'string' || (typeof document === 'object' && document.proof?.jwt);

		// define if SD-JWT
		const isSDJwt =
			isJWT && (typeof document === 'string' ? SDJwt.isSDJwt(document) : SDJwt.isSDJwt(document.proof.jwt));

		// detect document type - case: JWT
		if (isJWT && !isSDJwt) return AugmentedDocumentFormats.jwt;

		// detect document type - case: SD-JWT
		if (isSDJwt) return AugmentedDocumentFormats.sdjwt;

		// detect document type - case: EIP712
		if (typeof document !== 'string' && document?.proof?.type === 'EthereumEip712Signature2021')
			return AugmentedDocumentFormats.eip712;

		// detect document type - case: JSONLD
		return AugmentedDocumentFormats.jsonld;
	}
}
