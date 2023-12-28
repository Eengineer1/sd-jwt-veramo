import { IAgentPlugin, IIdentifier, IKey, IKeyManagerSignArgs } from '@veramo/core-types';
import { extractIssuer, processEntryToArray, MANDATORY_CREDENTIAL_CONTEXT } from '@veramo/utils';
import {
	ICredentialSDJwt,
	IRequiredContext,
	ICreateVerifiableCredentialSDJwtArgs,
	TCreateVerifiableCredentialSDJwtResult,
} from '../types/ICredentialSDJwt.js';
import { VeramoCompactAsyncJWTCryptoProvider } from '../crypto-provider/VeramoCompactAsyncJWTCryptoProvider.js';
import { SDJwt, SDPayload } from '@eengineer1/sd-jwt-ts-node';
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
		const credentialContext = processEntryToArray(args.credential['@context'], MANDATORY_CREDENTIAL_CONTEXT);

		// define credential type
		const credentialType = processEntryToArray(args.credential.type, 'VerifiableCredential');

		// define issuance date
		const issuanceDate = new Date().toISOString();

    // validate expiration date
    if (args.credential.expirationDate) {
      // define expiration date
      const expirationDate = args.credential.expirationDate instanceof Date
        ? args.credential.expirationDate
        : new Date(args.credential.expirationDate);

      // throw, if not applicable
      if (expirationDate < new Date(issuanceDate)) {
        throw new Error('invalid_argument: credential.expirationDate must be in the future');
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
				throw new Error(`invalid_argument: credential.issuer must be a DID managed by this agent. ${e}`);
			}
		})();

    // define jwt crypto provider
    const jwtCryptoProvider = new VeramoCompactAsyncJWTCryptoProvider();

    // define sd payload
    const sdPayload = args.undisclosedFields
      ? SDPayload.createSDPayloadFromFullAndUndisclosedPayload(args.credential, args.undisclosedFields)
      : await async function () {
        // use sd map, if provided
        return args.sdMap
          ? SDPayload.createSDPayload(args.credential, args.sdMap)
          : SDPayload.createSDPayloadFromFullAndUndisclosedPayload(args.credential, {});
      }();

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
        alg: key.type === 'Secp256k1' ? 'ES256K-R' : key.type === 'Secp256r1' ? 'ES256' : 'EdDSA',
      });

      // return
      return {
        sdJwt,
      };
    } catch (error) {
      // track error trace
      debug(error)

      // throw error
      throw new Error(`invalid_credential: Could not sign credential. ${error}`)
    }
	}

  /**
   * {@inheritDoc ICredentialSDJwt.createVerifiablePresentationSDJwt}
   */
  async createVerifiablePresentationSDJwt(
    args: ICreateVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<TCreateVerifiableCredentialSDJwtResult> {
    // TODO: implement
    throw new Error('not_implemented: createVerifiablePresentationSDJwt');
  }

  /**
   * {@inheritDoc ICredentialSDJwt.verifyVerifiableCredentialSDJwt}
   */
  async verifyVerifiableCredentialSDJwt(
    args: ICreateVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<TCreateVerifiableCredentialSDJwtResult> {
    // TODO: implement
    throw new Error('not_implemented: verifyVerifiableCredentialSDJwt');
  }

  /**
   * {@inheritDoc ICredentialSDJwt.verifyVerifiablePresentationSDJwt}
   */
  async verifyVerifiablePresentationSDJwt(
    args: ICreateVerifiableCredentialSDJwtArgs,
    context: IRequiredContext
  ): Promise<TCreateVerifiableCredentialSDJwtResult> {
    // TODO: implement
    throw new Error('not_implemented: verifyVerifiablePresentationSDJwt');
  }

  private static pickSigningKey(identifier: IIdentifier, keyRef?: string): IKey {
    return !keyRef
      ? function () {
          const key = identifier.keys.find(
            (k) => k.type === 'Secp256k1' || k.type === 'Ed25519' || k.type === 'Secp256r1',
          )
          if (!key) throw Error(`key_not_found: No signing key for ${identifier.did}`)
          return key
        }()
      : function () {
          const key = identifier.keys.find((k) => k.kid === keyRef)
          if (!key) throw Error(`key_not_found: No signing key for ${identifier.did} with kid ${keyRef}`)
          return key
        }()
  }

  private static pickSigningAlgorithm(key: IKey): string {
    switch (key.type) {
      case 'Ed25519':
        return 'EdDSA'
      case 'Secp256r1':
        return 'ES256'
      default:
        return 'ES256K'
    }
  }
}
