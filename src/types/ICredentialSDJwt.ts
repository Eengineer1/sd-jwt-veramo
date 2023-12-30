import { JSONObject, SDJwt, SDMap, JWTVerificationResult } from '@eengineer1/sd-jwt-ts-node';
import {
	IPluginMethodMap,
	IAgentContext,
	CredentialPayload,
	IKeyManager,
	IDIDManager,
	IResolver,
	VerifiableCredential,
	PresentationPayload,
	VerifiablePresentation,
	W3CVerifiableCredential,
	VerificationPolicies,
	W3CVerifiablePresentation,
} from '@veramo/core-types';

/**
 * The augmented document formats constant enumerator defined in this plugin.
 *
 * @beta
 */
export const AugmentedDocumentFormats = {
	jwt: 'JWT',
	jsonld: 'JSONLD',
	eip712: 'EIP712',
	sdjwt: 'SDJWT',
} as const;

/**
 * The augmented document formats type defined in this plugin.
 *
 * @beta
 */
export type AugmentedDocumentFormat = (typeof AugmentedDocumentFormats)[keyof typeof AugmentedDocumentFormats];

/**
 * This interface describes the public API surface of this plugin.
 *
 * @beta
 */
export interface ICredentialSDJwt extends IPluginMethodMap {
	/**
	 * Create a signed SD-JWT credential.
	 * @param args - Arguments necessary for the creation of a SD-JWT credential.
	 * @param context - This reserved param is automatically added and handled by the framework, *do not override*
	 */
	createVerifiableCredentialSDJwt(
		args: ICreateVerifiableCredentialSDJwtArgs,
		context: IRequiredContext
	): Promise<TCreateVerifiableCredentialSDJwtResult>;

	/**
	 * Create a signed SD-JWT presentation.
	 * @param args - Arguments necessary for the creation of a SD-JWT presentation.
	 * @param context - This reserved param is automatically added and handled by the framework, *do not override*
	 */
	createVerifiablePresentationSDJwt(
		args: ICreateVerifiablePresentationSDJwtArgs,
		context: IRequiredContext
	): Promise<TCreateVerifiablePresentationSDJwtResult>;

	/**
	 * Verify a signed SD-JWT credential.
	 * @param args - Arguments necessary for the verification of a SD-JWT credential.
	 * @param context - This reserved param is automatically added and handled by the framework, *do not override*
	 */
	verifyVerifiableCredentialSDJwt(
		args: IVerifyVerifiableCredentialSDJwtArgs,
		context: IRequiredContext
	): Promise<TVerifyVerifiableCredentialSDJwtResult>;

	/**
	 * Verify a signed SD-JWT presentation.
	 * @param args - Arguments necessary for the verification of a SD-JWT presentation.
	 * @param context - This reserved param is automatically added and handled by the framework, *do not override*
	 */
	verifyVerifiablePresentationSDJwt(
		args: IVerifyVerifiablePresentationSDJwtArgs,
		context: IRequiredContext
	): Promise<TVerifyVerifiablePresentationSDJwtResult>;
}

/**
 * Arguments needed for {@link CredentialSDJwt.createVerifiableCredentialSDJwt}
 * To be able to export a plugin schema, your plugin methods should use an `args` parameter of a
 * named type or interface.
 *
 * @beta
 */
export interface ICreateVerifiableCredentialSDJwtArgs {
	/**
	 * The JSON payload of the Credential according to the
	 * {@link https://www.w3.org/TR/vc-data-model/#credentials | canonical model}.
	 *
	 * The signer of the Credential is chosen based on the `issuer.id` property
	 * of the `credential`.
	 *
	 * `@context`, `type` and `issuanceDate` will be added automatically if omitted.
	 */
	credential: CredentialPayload;

	/**
	 * [Optional] The non-selectively disclosed fields of the credential.
	 *
	 * If omitted, and no `sdMap` is specified, all fields will be selectively disclosed.
	 *
	 * Use either this or `sdMap`, if both are specified, `undisclosedFields` will be used.
	 */
	undisclosedFields?: JSONObject;

	/**
	 * [Optional] The SDMap of the credential, in case it is already known and / or
	 * decoy fields should be added, per field.
	 *
	 * If omitted, and no `undisclosedFields` is specified, all fields will be selectively disclosed.
	 *
	 * Use either this or `undisclosedFields`, if both are specified, `undisclosedFields` will be used.
	 */
	sdMap?: SDMap;

	/**
	 * [Optional] Remove payload members during JWT-JSON transformation. Defaults to `true`.
	 * See https://www.w3.org/TR/vc-data-model/#jwt-encoding
	 */
	removeOriginalFields?: boolean;

	/**
	 * [Optional] Whether to return the SDJwt as normalised credential payload as well. Defaults to `false`.
	 *
	 * Useful for horizontal credential composition, consistency and interoperability.
	 */
	returnNormalisedCredential?: boolean;

	/**
	 * [Optional] The ID of the key that should sign this credential.
	 * If this is not specified, the first matching key will be used.
	 */
	keyRef?: string;

	/**
	 * Pass-through options.
	 */
	[x: string]: any;
}

/**
 * Result of {@link CredentialSDJwt.createVerifiableCredentialSDJwt}
 * To be able to export a plugin schema, your plugin return types need to be Promises of a
 * named type or interface.
 *
 * @beta
 */
export type TCreateVerifiableCredentialSDJwtResult = {
	/**
	 * The signed SDJwt credential.
	 */
	sdJwt: SDJwt;

	/**
	 * The normalised signed credential, if `returnNormalisedCredential` was set to `true`.
	 */
	normalisedCredential?: VerifiableCredential;
};

/**
 * Arguments needed for {@link CredentialSDJwt.createVerifiablePresentationSDJwt}
 * To be able to export a plugin schema, your plugin methods should use an `args` parameter of a
 * named type or interface.
 *
 * @beta
 */
export interface ICreateVerifiablePresentationSDJwtArgs {
	/**
	 * The JSON payload of the Presentation according to the
	 * {@link https://www.w3.org/TR/vc-data-model/#presentations | canonical model}.
	 *
	 * The signer of the Presentation is chosen based on the `holder` property
	 * of the `presentation`
	 *
	 * `@context`, `type` and `issuanceDate` will be added automatically if omitted
	 */
	presentation: SDJwtPresentationPayload;

	/**
	 * Optional (only JWT) string challenge parameter to add to the verifiable presentation.
	 */
	challenge?: string;

	/**
	 * Optional string domain parameter to add to the verifiable presentation.
	 */
	domain?: string;

	/**
	 * Remove payload members during JWT-JSON transformation. Defaults to `true`.
	 * See https://www.w3.org/TR/vc-data-model/#jwt-encoding
	 */
	removeOriginalFields?: boolean;

	/**
	 * [Optional] Whether to return the SDJwt as normalised presentation payload as well. Defaults to `false`.
	 *
	 * Useful for horizontal presentation composition, consistency and interoperability.
	 */
	returnNormalisedPresentation?: boolean;

	/**
	 * [Optional] The ID of the key that should sign this presentation.
	 * If this is not specified, the first matching key will be used.
	 */
	keyRef?: string;

	/**
	 * Pass-through options.
	 */
	[x: string]: any;
}

/**
 * Result of {@link CredentialSDJwt.createVerifiablePresentationSDJwt}
 * To be able to export a plugin schema, your plugin return types need to be Promises of a
 * named type or interface.
 *
 * @beta
 */
export type TCreateVerifiablePresentationSDJwtResult = {
	/**
	 * The signed SDJwt presentation.
	 */
	sdJwtPresentation: string;

	/**
	 * The normalised signed presentation, if `returnNormalisedPresentation` was set to `true`.
	 */
	normalisedPresentation?: VerifiablePresentation;
};

/**
 * Arguments needed for {@link CredentialSDJwt.verifyVerifiableCredentialSDJwt}
 * To be able to export a plugin schema, your plugin methods should use an `args` parameter of a
 * named type or interface.
 *
 * @beta
 */
export interface IVerifyVerifiableCredentialSDJwtArgs {
	/**
	 * The Verifiable Credential object according to the
	 * {@link https://www.w3.org/TR/vc-data-model/#credentials | canonical model} or the JWT representation.
	 *
	 * The signer of the Credential is verified based on the `issuer.id` property
	 * of the `credential` or the `iss` property of the JWT payload respectively.
	 *
	 */
	credential: W3CVerifiableCredential;

	/**
	 * Overrides specific aspects of credential verification, where possible.
	 */
	policies?: VerificationPolicies;

	/**
	 * Pass-through options.
	 */
	[x: string]: any;
}

/**
 * Result of {@link CredentialSDJwt.verifyVerifiableCredentialSDJwt}
 * To be able to export a plugin schema, your plugin return types need to be Promises of a
 * named type or interface.
 *
 * @beta
 */
export type TVerifyVerifiableCredentialSDJwtResult = JWTVerificationResult;

/**
 * Arguments needed for {@link CredentialSDJwt.verifyVerifiablePresentationSDJwt}
 * To be able to export a plugin schema, your plugin methods should use an `args` parameter of a
 * named type or interface.
 *
 * @beta
 */
export interface IVerifyVerifiablePresentationSDJwtArgs {
	/**
	 * The Verifiable Presentation object according to the
	 * {@link https://www.w3.org/TR/vc-data-model/#presentations | canonical model} or the JWT representation.
	 *
	 * The signer of the Presentation is verified based on the `holder` property
	 * of the `presentation` or the `iss` property of the JWT payload respectively.
	 */
	presentation: W3CVerifiablePresentation;

	/**
	 * Optional (only for JWT) string challenge parameter to verify the verifiable presentation against.
	 */
	challenge?: string;

	/**
	 * Optional (only for JWT) string domain parameter to verify the verifiable presentation against.
	 */
	domain?: string;

	/**
	 * Overrides specific aspects of credential verification, where possible.
	 */
	policies?: VerificationPolicies;

	/**
	 * Pass-through options.
	 */
	[x: string]: any;
}

/**
 * Result of {@link CredentialSDJwt.verifyVerifiablePresentationSDJwt}
 * To be able to export a plugin schema, your plugin return types need to be Promises of a
 * named type or interface.
 *
 * @beta
 */
export type TVerifyVerifiablePresentationSDJwtResult = JWTVerificationResult;

/**
 * The SDJwt presentation payload, extended with additional selective disclosure options and holder JWTs.
 *
 * @beta
 */
export type SDJwtPresentationPayload = PresentationPayload & {
	/**
	 * The selection of disclosures for this presentation, per credential, if any, defined as SDMap.
	 *
	 * Set as `null` if no selective disclosure maps are defined per credential, retaining the original credential order.
	 */
	presentWithSDMap?: (SDMap | null)[];

	/**
	 * The holder JWT for this presentation, per credential, if any, defined as JWT.
	 *
	 * Set as `null` if no holder JWTs are defined per credential, retaining the original credential order.
	 */
	presentWithHolderJwt?: (string | null)[];
};

/**
 * This context describes the requirements of this plugin.
 * For this plugin to function properly, the agent needs to also have other plugins installed that implement the
 * interfaces declared here.
 * You can also define requirements on a more granular level, for each plugin method or event handler of your plugin.
 *
 * @beta
 */
export type IRequiredContext = IAgentContext<IDIDManager & IResolver & IKeyManager>;
