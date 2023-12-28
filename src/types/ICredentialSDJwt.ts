import { JSONObject, SDJwt, SDMap } from '@eengineer1/sd-jwt-ts-node';
import {
	IPluginMethodMap,
	IAgentContext,
	CredentialPayload,
	IKeyManager,
	IDIDManager,
	IResolver,
} from '@veramo/core-types';

/**
 * This interface describes the public API surface of this plugin.
 *
 * @beta
 */
export interface ICredentialSDJwt extends IPluginMethodMap {
	createVerifiableCredentialSDJwt(
		args: ICreateVerifiableCredentialSDJwtArgs,
		context: IRequiredContext
	): Promise<TCreateVerifiableCredentialSDJwtResult>;

	createVerifiablePresentationSDJwt(
		args: ICreateVerifiablePresentationSDJwtArgs,
		context: IRequiredContext
	): Promise<TCreateVerifiablePresentationSDJwtResult>;

	verifyVerifiableCredentialSDJwt(
		args: IVerifyVerifiableCredentialSDJwtArgs,
		context: IRequiredContext
	): Promise<TVerifyVerifiableCredentialSDJwtResult>;

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
	 * Remove payload members during JWT-JSON transformation. Defaults to `true`.
	 * See https://www.w3.org/TR/vc-data-model/#jwt-encoding
	 */
	removeOriginalFields?: boolean;

	/**
	 * [Optional] The ID of the key that should sign this credential.
	 * If this is not specified, the first matching key will be used.
	 */
	keyRef?: string;

	/**
	 * Passthrough options.
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
	 * The signed SDJwt.
	 */
	sdJwt: SDJwt;
};

/**
 * Arguments needed for {@link CredentialSDJwt.createVerifiablePresentationSDJwt}
 * To be able to export a plugin schema, your plugin methods should use an `args` parameter of a
 * named type or interface.
 *
 * @beta
 */
export interface ICreateVerifiablePresentationSDJwtArgs {}

/**
 * Result of {@link CredentialSDJwt.createVerifiablePresentationSDJwt}
 * To be able to export a plugin schema, your plugin return types need to be Promises of a
 * named type or interface.
 *
 * @beta
 */
export type TCreateVerifiablePresentationSDJwtResult = {};

/**
 * Arguments needed for {@link CredentialSDJwt.verifyVerifiableCredentialSDJwt}
 * To be able to export a plugin schema, your plugin methods should use an `args` parameter of a
 * named type or interface.
 *
 * @beta
 */
export interface IVerifyVerifiableCredentialSDJwtArgs {}

/**
 * Result of {@link CredentialSDJwt.verifyVerifiableCredentialSDJwt}
 * To be able to export a plugin schema, your plugin return types need to be Promises of a
 * named type or interface.
 *
 * @beta
 */
export type TVerifyVerifiableCredentialSDJwtResult = {};

/**
 * Arguments needed for {@link CredentialSDJwt.verifyVerifiablePresentationSDJwt}
 * To be able to export a plugin schema, your plugin methods should use an `args` parameter of a
 * named type or interface.
 *
 * @beta
 */
export interface IVerifyVerifiablePresentationSDJwtArgs {}

/**
 * Result of {@link CredentialSDJwt.verifyVerifiablePresentationSDJwt}
 * To be able to export a plugin schema, your plugin return types need to be Promises of a
 * named type or interface.
 *
 * @beta
 */
export type TVerifyVerifiablePresentationSDJwtResult = {};

/**
 * This context describes the requirements of this plugin.
 * For this plugin to function properly, the agent needs to also have other plugins installed that implement the
 * interfaces declared here.
 * You can also define requirements on a more granular level, for each plugin method or event handler of your plugin.
 *
 * @beta
 */
export type IRequiredContext = IAgentContext<IDIDManager & IResolver & IKeyManager>;
