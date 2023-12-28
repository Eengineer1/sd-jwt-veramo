import { createLocalAgent } from './testutils.test.js';

describe('Agent', () => {
    it('should be able to be instantiated within a new agent', () => {
        // generate agent
        const agent = createLocalAgent();

        // expect agent methods
        expect(agent.createVerifiableCredentialSDJwt).toBeDefined();
        expect(agent.createVerifiablePresentationSDJwt).toBeDefined();
        expect(agent.verifyVerifiableCredentialSDJwt).toBeDefined();
        expect(agent.verifyVerifiablePresentationSDJwt).toBeDefined();
    });
});