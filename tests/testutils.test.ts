import { GasPrice } from "@cosmjs/stargate"

export const faucet = {
    prefix: 'cheqd',
    minimalDenom: 'zarx',
    mnemonic: 'sketch mountain erode window enact net enrich smoke claim kangaroo another visual write meat latin bacon pulp similar forum guilt father state erase bright',
    address: 'cheqd1rnr5jrt4exl0samwj0yegv99jeskl0hsxmcz96',
}

export const localnet = {
    network: 'testnet',
    rpcUrl: 'http://localhost:26657',
    gasPrice: GasPrice.fromString( `50${faucet.minimalDenom}` )
}

export const json_content = "{\"message\": \"hello world\"}"

export const image_content = 'iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAABmvDolAAAAA1BMVEW10NBjBBbqAAAAH0lEQVRoge3BAQ0AAADCoPdPbQ43oAAAAAAAAAAAvg0hAAABmmDh1QAAAABJRU5ErkJggg' as const

export const default_content = '<p>Test file content</p>'

export function containsAll<T>(array: T[], values: T[]): boolean {
    return values.every(value => array.includes(value))
}

export function containsAllButOmittedFields<T extends Record<string, any>>(array: T[], values: T[], omit: string[]): boolean {
    const replacer = (key: string, value: any) => omit.includes(key) ? undefined : value
    return values.every(value => array.some(item => JSON.stringify(item, replacer) === JSON.stringify(value, replacer)))
}