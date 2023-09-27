import {
    MsgCreateDidDoc,
    MsgCreateDidDocPayload,
    VerificationMethod
} from "@canow-co/canow-proto/dist/cheqd/did/v2"
import {
    DirectSecp256k1HdWallet,
    Registry
} from "@cosmjs/proto-signing"
import { BroadcastTxError, DeliverTxResponse, SigningStargateClient } from "@cosmjs/stargate"
import { EdDSASigner } from "did-jwt"
import { typeUrlMsgCreateDidDoc } from '../src/modules/did'
import { CheqdSigningStargateClient } from "../src/signer"
import {
    ISignInputs,
    MethodSpecificIdAlgo,
    VerificationMethods
} from "../src/types"
import {
    fromString,
    toString
} from 'uint8arrays'
import {
    createDidPayload,
    createDidVerificationMethod,
    createKeyPairBase64,
    createVerificationKeys,
    toVerificationRelationships,
    validateSpecCompliantPayload
} from '../src/utils';
import {
    localnet,
    faucet
} from "./testutils.test"
import { verify } from "@stablelib/ed25519"
import { v4 } from "uuid"

const nonExistingDid = "did:cAnOw:fantasticnet:123"
const nonExistingKeyId = 'did:cAnOw:fantasticnet:123#key-678'
const nonExistingPublicKeyMultibase = '1234567890'
const nonExistingVerificationMethod = 'ExtraTerrestrialVerificationKey2045'
const nonExistingVerificationDidDocument = {
    "authentication": [
        "did:canow:testnet:z6Jn6NmYkaCepQe2#key-1"
    ],
    "controller": [
        "did:canow:testnet:z6Jn6NmYkaCepQe2"
    ],
    "id": "did:canow:testnet:z6Jn6NmYkaCepQe2",
    "verificationMethod": [
        {
            "controller": "did:canow:testnet:z6Jn6NmYkaCepQe2",
            "id": "did:canow:testnet:z6Jn6NmYkaCepQe2#key-1",
            "publicKeyMultibase": "z6Jn6NmYkaCepQe29vgCZQhFfRkN3YpEPiu14F8HbbmqW",
            "type": nonExistingVerificationMethod
        }
    ]
}

describe('CheqdSigningStargateClient', () => {
    describe('constructor', () => {
        it('can be instantiated & works for cheqd networks', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)
            expect(signer).toBeInstanceOf(CheqdSigningStargateClient)
        })

        it('can be constructed with cheqd custom registry', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const registry = new Registry()
            registry.register(typeUrlMsgCreateDidDoc, MsgCreateDidDoc)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet, { registry })
            expect(signer.registry.lookupType(typeUrlMsgCreateDidDoc)).toBe(MsgCreateDidDoc)
        })
    })

    describe('getDidSigner', () => {
        it('can get a signer for a did', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)
            const keyPair = createKeyPairBase64()
            const verificationKeys = createVerificationKeys(keyPair.publicKey, MethodSpecificIdAlgo.Base58, 'key-1')
            const verificationMethods = createDidVerificationMethod([VerificationMethods.Ed255192020], [verificationKeys])
            const didPayload = createDidPayload(verificationMethods, [verificationKeys])
            const { protobufVerificationMethod } = validateSpecCompliantPayload(didPayload)

            const didSigner = await signer.getDidSigner(didPayload.verificationMethod![0].id, protobufVerificationMethod!)

            expect(didSigner).toBe(EdDSASigner)
        })

        it('should throw for a non-supported verification method', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            await expect(signer.getDidSigner(nonExistingVerificationDidDocument.verificationMethod[0].id, nonExistingVerificationDidDocument.verificationMethod)).rejects.toThrow()
        })

        it('should throw for non-matching verification method id', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)
            const keyPair = createKeyPairBase64()
            const verificationKeys = createVerificationKeys(keyPair.publicKey, MethodSpecificIdAlgo.Base58, 'key-1')
            const verificationMethods = createDidVerificationMethod([VerificationMethods.Ed255192020], [verificationKeys])
            const payload = createDidPayload(verificationMethods, [verificationKeys])
            const { protobufVerificationMethod } = validateSpecCompliantPayload(payload)

            await expect(signer.getDidSigner(nonExistingKeyId, protobufVerificationMethod!)).rejects.toThrow()
        })
    })

    describe('checkDidSigners', () => {
        it('it should instantiate a signer for a did', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)
            const keyPair = createKeyPairBase64()
            const verificationKeys = createVerificationKeys(keyPair.publicKey, MethodSpecificIdAlgo.Base58, 'key-1')
            const verificationMethods = createDidVerificationMethod([VerificationMethods.Ed255192020], [verificationKeys])
            const payload = createDidPayload(verificationMethods, [verificationKeys])
            const { protobufVerificationMethod } = validateSpecCompliantPayload(payload)
            const didSigners = await signer.checkDidSigners(protobufVerificationMethod)

            expect(didSigners[VerificationMethods.Ed255192020]).toBe(EdDSASigner)
        })

        it('should instantiate multiple signers for a did with multiple verification methods', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)
            const keyPair1 = createKeyPairBase64()
            const keyPair2 = createKeyPairBase64()
            const keyPair3 = createKeyPairBase64()
            const verificationKeys1 = createVerificationKeys(keyPair1.publicKey, MethodSpecificIdAlgo.Base58, 'key-1')
            const verificationKeys2 = createVerificationKeys(keyPair2.publicKey, MethodSpecificIdAlgo.Base58, 'key-2')
            const verificationKeys3 = createVerificationKeys(keyPair3.publicKey, MethodSpecificIdAlgo.Base58, 'key-3')
            const verificationMethods = createDidVerificationMethod([VerificationMethods.Ed255192020, VerificationMethods.JWK, VerificationMethods.Ed255192018], [verificationKeys1, verificationKeys2, verificationKeys3])

            const payload = createDidPayload(verificationMethods, [verificationKeys1, verificationKeys2, verificationKeys3])
            const { protobufVerificationMethod } = validateSpecCompliantPayload(payload)

            const didSigners = await signer.checkDidSigners(protobufVerificationMethod)

            expect(didSigners[VerificationMethods.Ed255192020]).toBe(EdDSASigner)
            expect(didSigners[VerificationMethods.JWK]).toBe(EdDSASigner)
            expect(didSigners[VerificationMethods.Ed255192018]).toBe(EdDSASigner)
        })

        it('should throw for non-supported verification method', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)
            const verificationMethod: Partial<VerificationMethod> = {
                id: nonExistingKeyId,
                verificationMethodType: nonExistingVerificationMethod,
                controller: nonExistingDid,
                verificationMaterial: JSON.stringify({publicKeyMultibase: nonExistingPublicKeyMultibase})
            }

            await expect(signer.checkDidSigners([VerificationMethod.fromPartial(verificationMethod)])).rejects.toThrow()
        })
    })

    describe('signcreateDidDocTx', () => {
        it('should sign a did tx with valid signature', async () => {
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)
            const keyPair = createKeyPairBase64()
            const verificationKeys = createVerificationKeys(keyPair.publicKey, MethodSpecificIdAlgo.Base58, 'key-1')
            const verificationMethods = createDidVerificationMethod([VerificationMethods.Ed255192020], [verificationKeys])
            const didPayload = createDidPayload(verificationMethods, [verificationKeys])
            const signInputs: ISignInputs[] = [
                {
                    verificationMethodId: didPayload.verificationMethod![0].id,
                    privateKeyHex: toString(fromString(keyPair.privateKey, 'base64'), 'hex')
                }
            ]
            const { protobufVerificationMethod, protobufService } = validateSpecCompliantPayload(didPayload)
            const versionId = v4()
            const payload = MsgCreateDidDocPayload.fromPartial({
                context: <string[]>didPayload?.['@context'],
                id: didPayload.id,
                controller: <string[]>didPayload.controller,
                verificationMethod: protobufVerificationMethod,
                authentication: toVerificationRelationships(didPayload.authentication),
                assertionMethod: toVerificationRelationships(didPayload.assertionMethod),
                capabilityInvocation: toVerificationRelationships(didPayload.capabilityInvocation),
                capabilityDelegation: toVerificationRelationships(didPayload.capabilityDelegation),
                keyAgreement: toVerificationRelationships(didPayload.keyAgreement),
                service: protobufService,
                alsoKnownAs: <string[]>didPayload.alsoKnownAs,
                versionId: versionId
            })
            const signInfos = await signer.signcreateDidDocTx(signInputs, payload)
            const publicKeyRaw = fromString(keyPair.publicKey, 'base64')
            const messageRaw = MsgCreateDidDocPayload.encode(payload).finish()

            const verified = verify(
                publicKeyRaw,
                messageRaw,
                signInfos[0].signature
            )

            expect(verified).toBe(true)
        })
    })

    describe('broadcastTx', () => {
        function createSuccessResult(): DeliverTxResponse {
            return {
                code: 0,
                height: 1,
                transactionHash: '0f0f',
                events: [],
                gasUsed: 0,
                gasWanted: 0
            }
        }

        function createFailureResult({ code }: { code: number }): DeliverTxResponse {
            if (code === 0) {
                throw Error('Failure result must have non-zero code')
            }
            return {
                code,
                height: 0,
                transactionHash: '',
                events: [],
                gasUsed: 0,
                gasWanted: 0
            }
        }

        afterEach(() => {
            jest.restoreAllMocks()
        })

        it('should return successful result from super.broadcastTx right away', async () => {
            const successResult = createSuccessResult()
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx').mockResolvedValue(successResult)
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(successResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(1)
        })

        it('should return non-sequence error result from super.broadcastTx right away', async () => {
            const insufficientFundsResult = createFailureResult({ code: 5 })
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx').mockResolvedValue(insufficientFundsResult)
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(insufficientFundsResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(1)
        })

        it('should raise non-sequence error from super.broadcastTx right away', async () => {
            const insufficientFundsError = new BroadcastTxError(5, 'sdk', 'Error message.')
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx').mockRejectedValue(insufficientFundsError)
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            await expect(signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )).rejects.toThrow(insufficientFundsError)

            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(1)
        })

        it('should return successful result from super.broadcastTx after 1 wrong sequence result', async () => {
            const wrongSequenceResult = createFailureResult({ code: 32 })
            const successResult = createSuccessResult()
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValue(successResult)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(successResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(2)
        })

        it('should return non-sequence error result from super.broadcastTx after 1 wrong sequence result', async () => {
            const wrongSequenceResult = createFailureResult({ code: 32 })
            const insufficientFundsResult = createFailureResult({ code: 5 })
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValue(insufficientFundsResult)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(insufficientFundsResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(2)
        })

        it('should raise non-sequence error from super.broadcastTx after 1 wrong sequence result', async () => {
            const wrongSequenceResult = createFailureResult({ code: 32 })
            const insufficientFundsError = new BroadcastTxError(5, 'sdk', 'Error message.')
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockRejectedValue(insufficientFundsError)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            await expect(signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )).rejects.toThrow(insufficientFundsError)

            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(2)
        })

        it('should return successful result from super.broadcastTx after 1 wrong sequence error', async () => {
            const wrongSequenceError = new BroadcastTxError(32, 'sdk', 'Error message.')
            const successResult = createSuccessResult()
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockResolvedValue(successResult)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(successResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(2)
        })

        it('should return non-sequence error result from super.broadcastTx after 1 wrong sequence error', async () => {
            const wrongSequenceError = new BroadcastTxError(32, 'sdk', 'Error message.')
            const insufficientFundsResult = createFailureResult({ code: 5 })
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockResolvedValue(insufficientFundsResult)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(insufficientFundsResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(2)
        })

        it('should raise non-sequence error from super.broadcastTx after 1 wrong sequence error', async () => {
            const wrongSequenceError = new BroadcastTxError(32, 'sdk', 'Error message.')
            const insufficientFundsError = new BroadcastTxError(5, 'sdk', 'Error message.')
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValue(insufficientFundsError)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            await expect(signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )).rejects.toThrow(insufficientFundsError)

            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(2)
        })

        it('should return successful result from super.broadcastTx after maxRetriesCount wrong sequence result', async () => {
            const wrongSequenceResult = createFailureResult({ code: 32 })
            const successResult = createSuccessResult()
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValue(successResult)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(successResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(6)
        })

        it('should return non-sequence error result from super.broadcastTx after maxRetriesCount wrong sequence result', async () => {
            const wrongSequenceResult = createFailureResult({ code: 32 })
            const insufficientFundsResult = createFailureResult({ code: 5 })
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValue(insufficientFundsResult)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(insufficientFundsResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(6)
        })

        it('should raise non-sequence error from super.broadcastTx after maxRetriesCount wrong sequence result', async () => {
            const wrongSequenceResult = createFailureResult({ code: 32 })
            const insufficientFundsError = new BroadcastTxError(5, 'sdk', 'Error message.')
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockResolvedValueOnce(wrongSequenceResult)
            superBroadcastTxSpy.mockRejectedValue(insufficientFundsError)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            await expect(signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )).rejects.toThrow(insufficientFundsError)

            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(6)
        })

        it('should return successful result from super.broadcastTx after maxRetriesCount wrong sequence error', async () => {
            const wrongSequenceError = new BroadcastTxError(32, 'sdk', 'Error message.')
            const successResult = createSuccessResult()
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockResolvedValue(successResult)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(successResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(6)
        })

        it('should return non-sequence error result from super.broadcastTx after maxRetriesCount wrong sequence error', async () => {
            const wrongSequenceError = new BroadcastTxError(32, 'sdk', 'Error message.')
            const insufficientFundsResult = createFailureResult({ code: 5 })
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockResolvedValue(insufficientFundsResult)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(insufficientFundsResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(6)
        })

        it('should raise non-sequence error from super.broadcastTx after maxRetriesCount wrong sequence error', async () => {
            const wrongSequenceError = new BroadcastTxError(32, 'sdk', 'Error message.')
            const insufficientFundsError = new BroadcastTxError(5, 'sdk', 'Error message.')
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx')
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValueOnce(wrongSequenceError)
            superBroadcastTxSpy.mockRejectedValue(insufficientFundsError)

            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            await expect(signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )).rejects.toThrow(insufficientFundsError)

            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(6)
        })

        it('should return wrong sequence result from super.broadcastTx on maxRetriesCount+1 unsuccessful attempt', async () => {
            const wrongSequenceResult = createFailureResult({ code: 32 })
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx').mockResolvedValue(wrongSequenceResult)
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            const result = await signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )

            expect(result).toEqual(wrongSequenceResult)
            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(6)
        })

        it('should raise wrong sequence error from super.broadcastTx on maxRetriesCount+1 unsuccessful attempt', async () => {
            const wrongSequenceError = new BroadcastTxError(32, 'sdk', 'Error message.')
            const superBroadcastTxSpy = jest.spyOn(SigningStargateClient.prototype, 'broadcastTx').mockRejectedValue(wrongSequenceError)
            const wallet = await DirectSecp256k1HdWallet.fromMnemonic(faucet.mnemonic)
            const signer = await CheqdSigningStargateClient.connectWithSigner(localnet.rpcUrl, wallet)

            await expect(signer.broadcastTx(
                new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
                undefined,
                undefined,
                5,
                10
            )).rejects.toThrow(wrongSequenceError)

            expect(superBroadcastTxSpy).toHaveBeenCalledTimes(6)
        })
    })
})