import { 
    IKeyPair, 
    IKeyValuePair, 
    ISignInputs, 
    VerificationMethods, 
    TMethodSpecificId, 
    MethodSpecificIdAlgo, 
    TVerificationKey, 
    TVerificationKeyPrefix, 
    CheqdNetwork, 
    IVerificationKeys,
    VerificationMethod,
    DIDDocument,
    SpecValidationResult,
    JsonWebKey,
} from "./types"
import {
    fromString,
    toString
} from 'uint8arrays'
import { bases } from "multiformats/basics"
import { base64ToBytes } from "did-jwt"
import {
    generateKeyPair,
    generateKeyPairFromSeed,
    KeyPair
} from '@stablelib/ed25519'
import { sha256 } from '@cosmjs/crypto'
import { v4 } from 'uuid'
import {
    VerificationMethod as ProtoVerificationMethod,
    Service as ProtoService,
    VerificationRelationship,
} from "@canow-co/canow-proto/dist/cheqd/did/v2"

export type TImportableEd25519Key = {
    publicKeyHex: string
    privateKeyHex: string
    kid: string
    type: "Ed25519"
}

export const contexts = {
	W3CDIDv1: "https://www.w3.org/ns/did/v1",
	W3CSuiteEd255192020: "https://w3id.org/security/suites/ed25519-2020/v1",
	W3CSuiteEd255192018: "https://w3id.org/security/suites/ed25519-2018/v1",
	W3CSuiteJws2020: "https://w3id.org/security/suites/jws-2020/v1",
} as const

const MULTICODEC_ED25519_HEADER = new Uint8Array([0xed, 0x01]);

export function isEqualKeyValuePair(kv1: IKeyValuePair[], kv2: IKeyValuePair[]): boolean {
    return kv1.every((item, index) => item.key === kv2[index].key && item.value === kv2[index].value)
}

export function createSignInputsFromImportableEd25519Key(key: TImportableEd25519Key, verificationMethod: VerificationMethod[]): ISignInputs {
    if (verificationMethod?.length === 0) throw new Error('No verification methods provided')

    const publicKey = fromString(key.publicKeyHex, 'hex')

    for(const method of verificationMethod) {
        switch (method?.type) {
            case VerificationMethods.Ed255192020:
                const publicKeyMultibase = toMultibaseRaw(publicKey)
                if (method.publicKeyMultibase === publicKeyMultibase) {
                    return {
                        verificationMethodId: method.id,
                        privateKeyHex: key.privateKeyHex
                    }
                }
            case VerificationMethods.Ed255192018:
                const publicKeyBase58 = bases['base58btc'].encode(publicKey).slice(1)
                if (method.publicKeyBase58 === publicKeyBase58) {
                    return {
                        verificationMethodId: method.id,
                        privateKeyHex: key.privateKeyHex
                    }
                }
            case VerificationMethods.JWK:
                const publicKeyJwk: JsonWebKey = {
                    crv: 'Ed25519',
                    kty: 'OKP',
                    x: toString( publicKey, 'base64url' )
                }
                if (JSON.stringify(method.publicKeyJwk) === JSON.stringify(publicKeyJwk)) {
                    return {
                        verificationMethodId: method.id,
                        privateKeyHex: key.privateKeyHex
                    }
                }
        }
    }

    throw new Error('No verification method type provided')
}

export function createKeyPairRaw(seed?: string): KeyPair {
    return seed ? generateKeyPairFromSeed(fromString(seed)) : generateKeyPair()
}

export function createKeyPairBase64(seed?: string): IKeyPair {
    const keyPair = seed ? generateKeyPairFromSeed(fromString(seed)) : generateKeyPair()
    return {
        publicKey: toString(keyPair.publicKey, 'base64'),
        privateKey: toString(keyPair.secretKey, 'base64'),
    }
}

export function createKeyPairHex(seed?: string): IKeyPair {
    const keyPair = createKeyPairRaw(seed)
    return {
        publicKey: toString(keyPair.publicKey, 'hex'),
        privateKey: toString(keyPair.secretKey, 'hex'),
    }
}

export function createVerificationKeys(publicKey: string, algo: MethodSpecificIdAlgo, key: TVerificationKey<TVerificationKeyPrefix, number>, network: CheqdNetwork = CheqdNetwork.Testnet): IVerificationKeys {
    let methodSpecificId: TMethodSpecificId
    let didUrl: IVerificationKeys['didUrl']

    publicKey = publicKey.length == 43 ? publicKey : toString(fromString(publicKey, 'hex'), 'base64')
    switch (algo) {
        case MethodSpecificIdAlgo.Base58:
            methodSpecificId = bases['base58btc'].encode(base64ToBytes(publicKey))
            didUrl = `did:canow:${network}:${(bases['base58btc'].encode((sha256(base64ToBytes(publicKey))).slice(0,16))).slice(1)}`
            return {
                methodSpecificId,
                didUrl,
                keyId: `${didUrl}#${key}`,
                publicKey,
            }
        case MethodSpecificIdAlgo.Uuid:
            methodSpecificId = bases['base58btc'].encode(base64ToBytes(publicKey))
            didUrl = `did:canow:${network}:${v4()}`
            return {
                methodSpecificId,
                didUrl,
                keyId: `${didUrl}#${key}`,
                publicKey,
            }
    }
}

export function createDidVerificationMethod(verificationMethodTypes: VerificationMethods[], verificationKeys: IVerificationKeys[], controller?: string): VerificationMethod[] {
    return verificationMethodTypes.map((type, _) => {
        const methodController = controller ?? verificationKeys[_].didUrl
        switch (type) {
            case VerificationMethods.Ed255192020:
                return {
                    id: verificationKeys[_].keyId,
                    type,
                    controller: methodController,
                    publicKeyMultibase: toMultibaseRaw(base64ToBytes(verificationKeys[_].publicKey))
                } as VerificationMethod
            case VerificationMethods.Ed255192018:
                return {
                    id: verificationKeys[_].keyId,
                    type,
                    controller: methodController,
                    publicKeyBase58: verificationKeys[_].methodSpecificId.slice(1)
                } as VerificationMethod
            case VerificationMethods.JWK:
                return {
                    id: verificationKeys[_].keyId,
                    type,
                    controller: methodController,
                    publicKeyJwk: {
                        crv: 'Ed25519',
                        kty: 'OKP',
                        x: toString( fromString( verificationKeys[_].publicKey, 'base64pad' ), 'base64url' )
                    }
                } as VerificationMethod
        }
    }) ?? []
}

export function createDidPayload(verificationMethods: VerificationMethod[], verificationKeys: IVerificationKeys[], controller?: string): DIDDocument {
    if (!verificationMethods || verificationMethods.length === 0)
        throw new Error('No verification methods provided')
    if (!verificationKeys || verificationKeys.length === 0)
        throw new Error('No verification keys provided')

    const did = verificationKeys[0].didUrl
    
    return {
        id: did,
        controller,
        verificationMethod: verificationMethods,
        authentication: verificationKeys.map(key => key.keyId)
    }
}

export function validateSpecCompliantPayload(didDocument: DIDDocument): SpecValidationResult {
    // id is required, validated on both compile and runtime
    if (!didDocument?.id) return { valid: false, error: 'id is required' }

    // verificationMethod is required
    if (!didDocument?.verificationMethod) return { valid: false, error: 'verificationMethod is required' }

    // verificationMethod must be an array
    if (!Array.isArray(didDocument?.verificationMethod)) return { valid: false, error: 'verificationMethod must be an array' }

    // verificationMethod types must be supported
    const protoVerificationMethod = didDocument.verificationMethod.map(toProtoVerificationMethod)

    const protoService = didDocument?.service?.map((s) => {
        return ProtoService.fromPartial({
            id: s?.id,
            serviceType: s?.type,
            serviceEndpoint: <string[]>s?.serviceEndpoint,
        })
    })

    return { valid: true, protobufVerificationMethod: protoVerificationMethod, protobufService: protoService }
}

export function toVerificationRelationships(values?: (string | VerificationMethod)[]): VerificationRelationship[] {
    if (!values) return []

    return values.map(value => {
        if (typeof value === 'string') {
            return { verificationMethodId: value, verificationMethod: undefined}
        }

        return {
            verificationMethodId: "",
            verificationMethod: toProtoVerificationMethod(value)
        }
    })
}

export function fromVerificationRelationships(context: string[], values: VerificationRelationship[]): (string | VerificationMethod)[] {
    return values.map(({verificationMethodId, verificationMethod}) => {
        if (verificationMethod) {
            return fromProtoVerificationMethod(context, verificationMethod)
        }

        return verificationMethodId
    })
}

export function toProtoVerificationMethod(vm: VerificationMethod): ProtoVerificationMethod {
    switch (vm?.type) {
        case VerificationMethods.Ed255192020:
            if (!vm.publicKeyMultibase) throw new Error('publicKeyMultibase is required')

            return ProtoVerificationMethod.fromPartial({
                id: vm.id,
                controller: vm.controller,
                verificationMethodType: VerificationMethods.Ed255192020,
                verificationMaterial: vm.publicKeyMultibase,
            })
        case VerificationMethods.JWK:
            if (!vm.publicKeyJwk) throw new Error('publicKeyJwk is required')

            return ProtoVerificationMethod.fromPartial({
                id: vm.id,
                controller: vm.controller,
                verificationMethodType: VerificationMethods.JWK,
                verificationMaterial: JSON.stringify(vm.publicKeyJwk),
            })
        case VerificationMethods.Ed255192018:
            if (!vm.publicKeyBase58) throw new Error('publicKeyBase58 is required')

            return ProtoVerificationMethod.fromPartial({
                id: vm.id,
                controller: vm.controller,
                verificationMethodType: VerificationMethods.Ed255192018,
                verificationMaterial: vm.publicKeyBase58,
            })
        default:
            throw new Error(`Unsupported verificationMethod type: ${vm?.type}`)
    }
}

export function fromProtoVerificationMethod(context: string[], vm: ProtoVerificationMethod): VerificationMethod {
    switch (vm.verificationMethodType) {
        case VerificationMethods.Ed255192020:
            if (!context.includes(contexts.W3CSuiteEd255192020))
                context = [...context, contexts.W3CSuiteEd255192020]
            return {
                id: vm.id,
                type: vm.verificationMethodType,
                controller: vm.controller,
                publicKeyMultibase: vm.verificationMaterial,
            }
        case VerificationMethods.JWK:
            if (!context.includes(contexts.W3CSuiteJws2020))
                context = [...context, contexts.W3CSuiteJws2020]
            return {
                id: vm.id,
                type: vm.verificationMethodType,
                controller: vm.controller,
                publicKeyJwk: JSON.parse(vm.verificationMaterial),
            }
        case VerificationMethods.Ed255192018:
            if (!context.includes(contexts.W3CSuiteEd255192018))
                context = [...context, contexts.W3CSuiteEd255192018]
            return {
                id: vm.id,
                type: vm.verificationMethodType,
                controller: vm.controller,
                publicKeyBase58: vm.verificationMaterial,
            }
        default:
            throw new Error('Unsupported verificationMethod type') // should never happen
    }
}

function toMultibaseRaw(key: Uint8Array) {
    const multibase = new Uint8Array(MULTICODEC_ED25519_HEADER.length + key.length);

    multibase.set(MULTICODEC_ED25519_HEADER);
    multibase.set(key, MULTICODEC_ED25519_HEADER.length);

    return bases['base58btc'].encode(multibase);
}
