import { BorshWriter, base64Encode, toHex } from './borsh'
import bs58 from 'bs58'
import { sha256 } from '@noble/hashes/sha256'
import { sha3_256 } from '@noble/hashes/sha3'

// Schema enums - these are the enum discriminants for Borsh serialization
export const SignatureType = {
  SuiDev: 0,
  PhantomSolanaEd25519: 1,
} as const

export const SignerType = {
  NewAccount: 0,
  Linked: 1,
  Temp: 2,
} as const

export type CreateAccountInput = {
  publicKeyHex: string // hex-encoded public key (string)
  signer: string // arbitrary string address
  createdAtMs: bigint
  nonce: bigint
  chainId: number // u16
  signatureType: number // SignatureType
  signerType: number // SignerType
  signatureBytes?: Uint8Array // if PhantomSolanaEd25519, put raw signature bytes
  hashBytes?: Uint8Array
}

export type NewCoinInput = {
  publicKeyHex: string
  signer: string
  name: string
  projectUri: string
  logoUri: string
  totalSupply: bigint
  maxSupply?: bigint
  canonicalChainId: bigint
  nonce: bigint
  chainId: number
  signatureType: number
  signerType: number
  signatureBytes?: Uint8Array
  hashBytes?: Uint8Array
}

export type MintInput = {
  publicKeyHex: string
  signer: string
  coinAddr: Uint8Array // 32 bytes
  accountAddr: Uint8Array // 32 bytes
  amount: bigint
  nonce: bigint
  chainId: number
  signatureType: number
  signerType: number
  signatureBytes?: Uint8Array
  hashBytes?: Uint8Array
}

export type TransferInput = {
  publicKeyHex: string
  signer: string
  coinAddr: Uint8Array // 32 bytes
  receiverAddr: Uint8Array // 32 bytes
  amount: bigint
  nonce: bigint
  chainId: number
  signatureType: number
  signerType: number
  signatureBytes?: Uint8Array
  hashBytes?: Uint8Array
}

export type CreateOrderbookInput = {
  publicKeyHex: string
  signer: string
  buyAsset: string // hex string of coin address
  sellAsset: string // hex string of coin address
  nonce: bigint
  chainId: number
  signatureType: number
  signerType: number
  signatureBytes?: Uint8Array
  hashBytes?: Uint8Array
}

export type NewLimitOrderInput = {
  publicKeyHex: string
  signer: string
  orderbookAddress: Uint8Array // 32 bytes
  isBuy: boolean
  amount: bigint
  tickPrice: bigint
  nonce: bigint
  chainId: number
  signatureType: number
  signerType: number
  signatureBytes?: Uint8Array
  hashBytes?: Uint8Array
}

export function serializeCreateAccountTx(input: CreateAccountInput): Uint8Array {
  const writer = new BorshWriter()

  // public_key: string (borsh string)
  writer.writeString(input.publicKeyHex)

  // signer: string (borsh string)
  writer.writeString(input.signer)

  // payload: enum PismoOperation (u8 tag + fields)
  writer.writeU8(1) // CreateAccount tag
  // CreateAccount is a unit variant - no additional fields

  // signature: Option<Vec<u8>>
  if (input.signatureBytes) {
    writer.writeU8(1) // Some
    writer.writeVecU8(input.signatureBytes)
  } else {
    writer.writeU8(0) // None
  }

  // hash: Option<Vec<u8>>
  if (input.hashBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.hashBytes)
  } else {
    writer.writeU8(0)
  }

  // nonce: u64 LE
  writer.writeU64LE(input.nonce)
  // chain_id: u16 LE
  writer.writeU16LE(input.chainId)
  // signature_type: enum SignatureType u8
  writer.writeU8(input.signatureType)
  // signer_type: enum SignerType u8
  writer.writeU8(input.signerType)

  return writer.concat()
}

export function serializeNewCoinTx(input: NewCoinInput): Uint8Array {
  const writer = new BorshWriter()

  // public_key: string
  writer.writeString(input.publicKeyHex)
  // signer: string
  writer.writeString(input.signer)

  // payload: NewCoin variant (tag = 4 based on enum order)
  writer.writeU8(4) // NewCoin tag
  writer.writeString(input.name)
  writer.writeString(input.projectUri)
  writer.writeString(input.logoUri)
  writer.writeU128LE(input.totalSupply)
  
  // max_supply: Option<u128>
  if (input.maxSupply !== undefined) {
    writer.writeU8(1) // Some
    writer.writeU128LE(input.maxSupply)
  } else {
    writer.writeU8(0) // None
  }
  
  writer.writeU64LE(input.canonicalChainId)

  // signature: Option<Vec<u8>>
  if (input.signatureBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.signatureBytes)
  } else {
    writer.writeU8(0)
  }

  // hash: Option<Vec<u8>>
  if (input.hashBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.hashBytes)
  } else {
    writer.writeU8(0)
  }

  writer.writeU64LE(input.nonce)
  writer.writeU16LE(input.chainId)
  writer.writeU8(input.signatureType)
  writer.writeU8(input.signerType)

  return writer.concat()
}

export function serializeMintTx(input: MintInput): Uint8Array {
  const writer = new BorshWriter()

  // public_key: string
  writer.writeString(input.publicKeyHex)
  // signer: string
  writer.writeString(input.signer)

  // payload: Mint variant (tag = 5 based on enum order)
  writer.writeU8(5) // Mint tag
  writer.writeBytes(input.coinAddr) // [u8; 32]
  writer.writeBytes(input.accountAddr) // [u8; 32]
  writer.writeU128LE(input.amount)

  // signature: Option<Vec<u8>>
  if (input.signatureBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.signatureBytes)
  } else {
    writer.writeU8(0)
  }

  // hash: Option<Vec<u8>>
  if (input.hashBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.hashBytes)
  } else {
    writer.writeU8(0)
  }

  writer.writeU64LE(input.nonce)
  writer.writeU16LE(input.chainId)
  writer.writeU8(input.signatureType)
  writer.writeU8(input.signerType)

  return writer.concat()
}

export function serializeTransferTx(input: TransferInput): Uint8Array {
  const writer = new BorshWriter()

  // public_key: string
  writer.writeString(input.publicKeyHex)
  // signer: string
  writer.writeString(input.signer)

  // payload: Transfer variant (tag = 6 based on enum order: Onramp=0, CreateAccount=1, LinkAccount=2, NoOp=3, NewCoin=4, Mint=5, Transfer=6)
  writer.writeU8(6) // Transfer tag
  writer.writeBytes(input.coinAddr) // [u8; 32]
  writer.writeBytes(input.receiverAddr) // [u8; 32]
  writer.writeU128LE(input.amount)

  // signature: Option<Vec<u8>>
  if (input.signatureBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.signatureBytes)
  } else {
    writer.writeU8(0)
  }

  // hash: Option<Vec<u8>>
  if (input.hashBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.hashBytes)
  } else {
    writer.writeU8(0)
  }

  writer.writeU64LE(input.nonce)
  writer.writeU16LE(input.chainId)
  writer.writeU8(input.signatureType)
  writer.writeU8(input.signerType)

  return writer.concat()
}

export function serializeCreateOrderbookTx(input: CreateOrderbookInput): Uint8Array {
  const writer = new BorshWriter()

  // public_key: string
  writer.writeString(input.publicKeyHex)
  // signer: string
  writer.writeString(input.signer)

  // payload: CreateOrderbook variant (tag = 7 based on enum order: Onramp=0, CreateAccount=1, LinkAccount=2, NoOp=3, NewCoin=4, Mint=5, Transfer=6, CreateOrderbook=7)
  writer.writeU8(7) // CreateOrderbook tag
  writer.writeString(input.buyAsset) // buy_asset: String
  writer.writeString(input.sellAsset) // sell_asset: String

  // signature: Option<Vec<u8>>
  if (input.signatureBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.signatureBytes)
  } else {
    writer.writeU8(0)
  }

  // hash: Option<Vec<u8>>
  if (input.hashBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.hashBytes)
  } else {
    writer.writeU8(0)
  }

  writer.writeU64LE(input.nonce)
  writer.writeU16LE(input.chainId)
  writer.writeU8(input.signatureType)
  writer.writeU8(input.signerType)

  return writer.concat()
}

export function serializeNewLimitOrderTx(input: NewLimitOrderInput): Uint8Array {
  const writer = new BorshWriter()

  // public_key: string
  writer.writeString(input.publicKeyHex)
  // signer: string
  writer.writeString(input.signer)

  // payload: NewLimitOrder variant (tag = 8 based on enum order: Onramp=0, CreateAccount=1, LinkAccount=2, NoOp=3, NewCoin=4, Mint=5, Transfer=6, CreateOrderbook=7, NewLimitOrder=8)
  writer.writeU8(8) // NewLimitOrder tag
  writer.writeBytes(input.orderbookAddress) // orderbook_address: [u8; 32]
  writer.writeU8(input.isBuy ? 1 : 0) // is_buy: bool
  writer.writeU128LE(input.amount) // amount: u128
  writer.writeU64LE(input.tickPrice) // tick_price: u64

  // signature: Option<Vec<u8>>
  if (input.signatureBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.signatureBytes)
  } else {
    writer.writeU8(0)
  }

  // hash: Option<Vec<u8>>
  if (input.hashBytes) {
    writer.writeU8(1)
    writer.writeVecU8(input.hashBytes)
  } else {
    writer.writeU8(0)
  }

  writer.writeU64LE(input.nonce)
  writer.writeU16LE(input.chainId)
  writer.writeU8(input.signatureType)
  writer.writeU8(input.signerType)

  return writer.concat()
}

export function buildCreateAccountPrehash(
  publicKeyHex: string,
  signer: string,
  createdAtMs: bigint,
  nonce: bigint,
  chainId: number,
): Uint8Array {
  // Backend hash = hash(public_key | signer | borsh(payload) | nonce | chain_id)
  const payloadWriter = new BorshWriter()
  payloadWriter.writeU8(1) // CreateAccount tag
  // CreateAccount is a unit variant - no additional fields
  const payloadBytes = payloadWriter.concat()

  const w = new BorshWriter()
  w.writeString(publicKeyHex)
  w.writeString(signer)
  w.writeBytes(payloadBytes)
  w.writeU64LE(nonce)
  w.writeU16LE(chainId)
  const preimage = w.concat()
  const digest = sha256(preimage)
  return new Uint8Array(digest)
}

export function buildNewCoinPrehash(
  publicKeyHex: string,
  signer: string,
  name: string,
  projectUri: string,
  logoUri: string,
  totalSupply: bigint,
  maxSupply: bigint | undefined,
  canonicalChainId: bigint,
  nonce: bigint,
  chainId: number,
): Uint8Array {
  // Build payload bytes
  const payloadWriter = new BorshWriter()
  payloadWriter.writeU8(4) // NewCoin tag
  payloadWriter.writeString(name)
  payloadWriter.writeString(projectUri)
  payloadWriter.writeString(logoUri)
  payloadWriter.writeU128LE(totalSupply)
  
  if (maxSupply !== undefined) {
    payloadWriter.writeU8(1)
    payloadWriter.writeU128LE(maxSupply)
  } else {
    payloadWriter.writeU8(0)
  }
  
  payloadWriter.writeU64LE(canonicalChainId)
  const payloadBytes = payloadWriter.concat()

  // Build envelope hash
  const w = new BorshWriter()
  w.writeString(publicKeyHex)
  w.writeString(signer)
  w.writeBytes(payloadBytes)
  w.writeU64LE(nonce)
  w.writeU16LE(chainId)
  const preimage = w.concat()
  const digest = sha256(preimage)
  return new Uint8Array(digest)
}

export function buildMintPrehash(
  publicKeyHex: string,
  signer: string,
  coinAddr: Uint8Array,
  accountAddr: Uint8Array,
  amount: bigint,
  nonce: bigint,
  chainId: number,
): Uint8Array {
  // Build payload bytes
  const payloadWriter = new BorshWriter()
  payloadWriter.writeU8(5) // Mint tag
  payloadWriter.writeBytes(coinAddr)
  payloadWriter.writeBytes(accountAddr)
  payloadWriter.writeU128LE(amount)
  const payloadBytes = payloadWriter.concat()

  // Build envelope hash
  const w = new BorshWriter()
  w.writeString(publicKeyHex)
  w.writeString(signer)
  w.writeBytes(payloadBytes)
  w.writeU64LE(nonce)
  w.writeU16LE(chainId)
  const preimage = w.concat()
  const digest = sha256(preimage)
  return new Uint8Array(digest)
}

export function buildTransferPrehash(
  publicKeyHex: string,
  signer: string,
  coinAddr: Uint8Array,
  receiverAddr: Uint8Array,
  amount: bigint,
  nonce: bigint,
  chainId: number,
): Uint8Array {
  // Build payload bytes
  const payloadWriter = new BorshWriter()
  payloadWriter.writeU8(6) // Transfer tag
  payloadWriter.writeBytes(coinAddr)
  payloadWriter.writeBytes(receiverAddr)
  payloadWriter.writeU128LE(amount)
  const payloadBytes = payloadWriter.concat()

  // Build envelope hash
  const w = new BorshWriter()
  w.writeString(publicKeyHex)
  w.writeString(signer)
  w.writeBytes(payloadBytes)
  w.writeU64LE(nonce)
  w.writeU16LE(chainId)
  const preimage = w.concat()
  const digest = sha256(preimage)
  return new Uint8Array(digest)
}

export function buildCreateOrderbookPrehash(
  publicKeyHex: string,
  signer: string,
  buyAsset: string,
  sellAsset: string,
  nonce: bigint,
  chainId: number,
): Uint8Array {
  // Build payload bytes
  const payloadWriter = new BorshWriter()
  payloadWriter.writeU8(7) // CreateOrderbook tag
  payloadWriter.writeString(buyAsset)
  payloadWriter.writeString(sellAsset)
  const payloadBytes = payloadWriter.concat()

  // Build envelope hash
  const w = new BorshWriter()
  w.writeString(publicKeyHex)
  w.writeString(signer)
  w.writeBytes(payloadBytes)
  w.writeU64LE(nonce)
  w.writeU16LE(chainId)
  const preimage = w.concat()
  const digest = sha256(preimage)
  return new Uint8Array(digest)
}

export function buildNewLimitOrderPrehash(
  publicKeyHex: string,
  signer: string,
  orderbookAddress: Uint8Array,
  isBuy: boolean,
  amount: bigint,
  tickPrice: bigint,
  nonce: bigint,
  chainId: number,
): Uint8Array {
  // Build payload bytes
  const payloadWriter = new BorshWriter()
  payloadWriter.writeU8(8) // NewLimitOrder tag
  payloadWriter.writeBytes(orderbookAddress)
  payloadWriter.writeU8(isBuy ? 1 : 0)
  payloadWriter.writeU128LE(amount)
  payloadWriter.writeU64LE(tickPrice)
  const payloadBytes = payloadWriter.concat()

  // Build envelope hash
  const w = new BorshWriter()
  w.writeString(publicKeyHex)
  w.writeString(signer)
  w.writeBytes(payloadBytes)
  w.writeU64LE(nonce)
  w.writeU16LE(chainId)
  const preimage = w.concat()
  const digest = sha256(preimage)
  return new Uint8Array(digest)
}

export function toBase64Borsh(bytes: Uint8Array): string {
  return base64Encode(bytes)
}

export function phantomMessageForCreateAccount(hash: Uint8Array, publicKeyHex: string): Uint8Array {
  // Deprecated: we now use a framed textual envelope per Phantom guidance.
  return hash
}

export function exampleSignerString(pubKeyBase58: string): string {
  // You may want to reflect the phantom account string
  return `sol:${pubKeyBase58}`
}

export function toDebugHex(bytes?: Uint8Array): string | undefined {
  return bytes ? toHex(bytes) : undefined
}

export function buildRequestBody(base64Borsh: string) {
  return {
    jsonrpc: '2.0',
    id: 1,
    method: 'submit_borsh_tx',
    params: [base64Borsh],
  }
}

export function buildPhantomEnvelope(params: {
  app: string
  purpose: string
  dataBytes: Uint8Array
  nonce: bigint
}): string {
  const dataB58 = bs58.encode(params.dataBytes)
  const nonceStr = params.nonce.toString(10)
  return [
    `APP: ${params.app}`,
    `PURPOSE: ${params.purpose}`,
    `DATA(b58): ${dataB58}`,
    `NONCE: ${nonceStr}`,
  ].join('\n')
}

// Helper functions for address derivation (client-side)
export function deriveCoinAddr(seedAddr: Uint8Array, name: string, canonicalChainId: bigint): Uint8Array {
  // Replicate the backend Sha3(seed_addr || name || canonical_chain_id) logic
  const nameBytes = new TextEncoder().encode(name)
  const chainIdBytes = new Uint8Array(8)
  new DataView(chainIdBytes.buffer).setBigUint64(0, canonicalChainId, true) // little endian
  
  const combined = new Uint8Array(seedAddr.length + nameBytes.length + chainIdBytes.length)
  combined.set(seedAddr, 0)
  combined.set(nameBytes, seedAddr.length)
  combined.set(chainIdBytes, seedAddr.length + nameBytes.length)
  
  // Use sha3_256 to match the backend exactly
  return sha3_256(combined)
}

export function deriveAccountAddr(version: number, signatureType: number, externalAddr: string): Uint8Array {
  // Replicate backend derive_account_addr logic exactly
  // Backend uses: Sha3("acct" || version || signature_type.internal_id() || external_addr_str.as_bytes())
  const externalAddrBytes = new TextEncoder().encode(externalAddr)
  const versionBytes = new Uint8Array([version])
  
  // Map frontend SignatureType to backend internal_id (must match backend exactly)
  // Backend: PhantomSolanaEd25519 => 2, SuiDev => 3
  let signatureTypeId: number
  if (signatureType === SignatureType.SuiDev) {
    signatureTypeId = 3 // Backend: SignatureType::SuiDev => 3
  } else if (signatureType === SignatureType.PhantomSolanaEd25519) {
    signatureTypeId = 2 // Backend: SignatureType::PhantomSolanaEd25519 => 2
  } else {
    throw new Error(`Unknown signature type: ${signatureType}`)
  }
  
  const sigTypeBytes = new Uint8Array(2)
  new DataView(sigTypeBytes.buffer).setUint16(0, signatureTypeId, true) // little endian
  
  const combined = new Uint8Array(4 + versionBytes.length + sigTypeBytes.length + externalAddrBytes.length)
  combined.set(new TextEncoder().encode('acct'), 0)
  combined.set(versionBytes, 4)
  combined.set(sigTypeBytes, 5)
  combined.set(externalAddrBytes, 7)
  
  // Use SHA3-256 to match backend exactly
  return sha3_256(combined)
}

export function deriveCoinStoreAddr(accountAddr: Uint8Array, coinAddr: Uint8Array): Uint8Array {
  // Replicate backend derive_coin_store_addr logic
  const combined = new Uint8Array(accountAddr.length + coinAddr.length)
  combined.set(accountAddr, 0)
  combined.set(coinAddr, accountAddr.length)
  
  // Use SHA3-256 to match backend exactly
  return sha3_256(combined)
}

// Orderbook address derivation (matches backend implementation)
export function deriveOrderbookAddr(buyAssetAddr: Uint8Array, sellAssetAddr: Uint8Array): Uint8Array {
  // Replicate backend derive_orderbook_addr logic: Sha3(buy_asset || sell_asset || "spot_orderbook")
  const combined = new Uint8Array(buyAssetAddr.length + sellAssetAddr.length + 14) // "spot_orderbook".length = 14
  combined.set(buyAssetAddr, 0)
  combined.set(sellAssetAddr, buyAssetAddr.length)
  combined.set(new TextEncoder().encode('spot_orderbook'), buyAssetAddr.length + sellAssetAddr.length)
  
  // Use SHA3-256 to match backend exactly
  return sha3_256(combined)
}

// View query helper (deprecated - use makeRpcCall from App component instead)
export async function viewQuery(address: string, type: string, additionalParams?: { signature_type?: number, external_address?: string }): Promise<any> {
  const params: any = { address, type }
  
  // Add additional parameters if provided (for Link queries)
  if (additionalParams) {
    Object.assign(params, additionalParams)
  }
  
  const res = await fetch('/rpc', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'view',
      params,
    }),
  })
  
  const json = await res.json()
  if (json.error) {
    throw new Error(`View query failed: ${json.error.message}`)
  }
  
  return json.result
}
