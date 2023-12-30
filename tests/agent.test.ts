import { isAsyncFunction } from 'util/types';
import { bootstrapLocalAgent, createLocalAgent, unsignedCredential } from './utils/testutils.test.js';
import { CredentialPayload } from '@veramo/core-types';
import { JSONObject } from '@eengineer1/sd-jwt-ts-node';

describe('agent', () => {
	afterAll(async () => {
		// redact private keys - case: issuer
		process.env.ISSUER_PRIVATE_KEY_HEX = '';

		// redact private keys - case: holder
		process.env.HOLDER_PRIVATE_KEY_HEX = '';
	});

	it('should be able to be instantiated within a new agent', async () => {
		// create agent
		const agent = createLocalAgent();

		// expect defined agent methods
		expect(agent.createVerifiableCredentialSDJwt).toBeDefined();
		expect(agent.createVerifiablePresentationSDJwt).toBeDefined();
		expect(agent.verifyVerifiableCredentialSDJwt).toBeDefined();
		expect(agent.verifyVerifiablePresentationSDJwt).toBeDefined();

		// expect asynchronous functional agent methods
		expect(isAsyncFunction(agent.createVerifiableCredentialSDJwt)).toBe(true);
		expect(isAsyncFunction(agent.createVerifiablePresentationSDJwt)).toBe(true);
		expect(isAsyncFunction(agent.verifyVerifiableCredentialSDJwt)).toBe(true);
		expect(isAsyncFunction(agent.verifyVerifiablePresentationSDJwt)).toBe(true);
	});

	it('should be able to create, sign and verify a verifiable credential SD-JWT', async () => {
		// create + bootstrap agent
		const { agent, issuer, holder } = await bootstrapLocalAgent(createLocalAgent());

		// define claimset
		const claimset = {
			...unsignedCredential,
			issuer: issuer.didDocument.id,
			credentialSubject: {
				...unsignedCredential.credentialSubject,
				id: holder.didDocument.id,
			},
		} satisfies CredentialPayload;

		// define undisclosed claimset
		const undisclosedClaimset = {
			'@context': claimset['@context'],
			type: claimset.type,
			issuanceDate: 'anything-truthy',
			credentialSubject: {
				id: claimset.credentialSubject.id,
				nestedSimple: claimset.credentialSubject.nestedSimple,
			},
		} satisfies JSONObject;

		// create + sign SD-JWT credential
		const { sdJwt, normalisedCredential } = await agent.createVerifiableCredentialSDJwt({
			credential: claimset,
			undisclosedFields: undisclosedClaimset,
			removeOriginalFields: true,
			returnNormalisedCredential: true,
		});

		// expect non-selectively disclosed fields to be removed from the undisclosed payload
		expect(sdJwt.undisclosedPayload?.['credentialSubject']).not.toHaveProperty('nestedArray');
		expect(sdJwt.undisclosedPayload?.['credentialSubject']).not.toHaveProperty('nestedObject');

		// expect selectively disclosed fields to be present in the undisclosed payload
		expect(sdJwt.undisclosedPayload).toHaveProperty('@context');
		expect(sdJwt.undisclosedPayload).toHaveProperty('type');
		expect(sdJwt.undisclosedPayload).toHaveProperty('issuanceDate');
		expect(sdJwt.undisclosedPayload).toHaveProperty('credentialSubject');
		expect(sdJwt.undisclosedPayload?.['credentialSubject']).toHaveProperty('id');
		expect(sdJwt.undisclosedPayload?.['credentialSubject']).toHaveProperty('nestedSimple');

		// expect selectively disclosed fields to equal the original claimset
		expect(sdJwt.undisclosedPayload?.['@context']).toEqual(claimset['@context']);
		expect(sdJwt.undisclosedPayload?.type).toEqual(claimset.type);
		expect((sdJwt.undisclosedPayload?.['credentialSubject'] as JSONObject)?.['id']).toEqual(
			claimset.credentialSubject.id
		);
		expect((sdJwt.undisclosedPayload?.['credentialSubject'] as JSONObject)?.['nestedSimple']).toEqual(
			claimset.credentialSubject.nestedSimple
		);

		// expect normalised credential fields to be present
		expect(normalisedCredential).toHaveProperty('proof');
		expect(normalisedCredential?.['proof']).toHaveProperty('jwt');
		expect(normalisedCredential?.['proof']).toHaveProperty('type');
		expect(normalisedCredential?.['proof']?.['jwt']).toEqual(sdJwt.jwt);
		expect(normalisedCredential?.['proof']?.['type']).toEqual('JwtProof2020');

		// verify SD-JWT credential
		const { verified, message } = await agent.verifyVerifiableCredentialSDJwt({
			credential: sdJwt.jwt,
		});

		// expect verification to be successful
		expect(verified).toBe(true);
		expect(message).toBeUndefined();
	});

	it('should be able to create, sign and verify a verifiable presentation SD-JWT', async () => {
		// create + bootstrap agent
		const { agent, issuer, holder } = await bootstrapLocalAgent(createLocalAgent());

		// define claimset
		const claimset = {
			...unsignedCredential,
			issuer: issuer.didDocument.id,
			credentialSubject: {
				...unsignedCredential.credentialSubject,
				id: holder.didDocument.id,
			},
		} satisfies CredentialPayload;

		// define undisclosed claimset
		const undisclosedClaimset = {
			'@context': claimset['@context'],
			type: claimset.type,
			issuanceDate: 'anything-truthy',
			credentialSubject: {
				id: claimset.credentialSubject.id,
				nestedSimple: claimset.credentialSubject.nestedSimple,
			},
		} satisfies JSONObject;

		// create + sign SD-JWT credential
		const { sdJwt, normalisedCredential } = await agent.createVerifiableCredentialSDJwt({
			credential: claimset,
			undisclosedFields: undisclosedClaimset,
			removeOriginalFields: true,
			returnNormalisedCredential: true,
		});

		// create + sign SD-JWT presentation
		const { sdJwtPresentation, normalisedPresentation } = await agent.createVerifiablePresentationSDJwt({
			presentation: {
				verifiableCredential: [sdJwt.jwt],
				holder: holder.didDocument.id,
			},
			removeOriginalFields: true,
			returnNormalisedPresentation: true,
		});

		// expect included credential to be present and equal to the signed SD-JWT credential, within the normalised presentation
		expect(normalisedPresentation?.verifiableCredential).toHaveLength(1);
		expect(normalisedPresentation?.verifiableCredential).toContainEqual(normalisedCredential);

		// verify SD-JWT presentation
		const { verified, message } = await agent.verifyVerifiablePresentationSDJwt({
			presentation: sdJwtPresentation,
		});

		// expect verification to be successful
		expect(verified).toBe(true);
		expect(message).toBeUndefined();
	});
});
