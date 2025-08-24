// Minimal Borsh helpers for this specific schema
// Strings: u32 LE length + utf8 bytes
// Vec<u8>: u32 LE length + bytes
// Enums: u8 tag then fields
// Numerics: little-endian

export class BorshWriter {
  private chunks: Uint8Array[] = []

  writeU8(value: number) {
    const a = new Uint8Array(1)
    a[0] = value & 0xff
    this.chunks.push(a)
  }

  writeU16LE(value: number) {
    const a = new Uint8Array(2)
    const v = value >>> 0
    a[0] = v & 0xff
    a[1] = (v >>> 8) & 0xff
    this.chunks.push(a)
  }

  writeU32LE(value: number) {
    const a = new Uint8Array(4)
    const v = value >>> 0
    a[0] = v & 0xff
    a[1] = (v >>> 8) & 0xff
    a[2] = (v >>> 16) & 0xff
    a[3] = (v >>> 24) & 0xff
    this.chunks.push(a)
  }

  writeU64LE(value: bigint) {
    const a = new Uint8Array(8)
    let v = value
    for (let i = 0; i < 8; i++) {
      a[i] = Number(v & 0xffn)
      v >>= 8n
    }
    this.chunks.push(a)
  }

  writeU128LE(value: bigint) {
    const a = new Uint8Array(16)
    let v = value
    for (let i = 0; i < 16; i++) {
      a[i] = Number(v & 0xffn)
      v >>= 8n
    }
    this.chunks.push(a)
  }

  writeBytes(bytes: Uint8Array) {
    this.chunks.push(bytes)
  }

  writeVecU8(bytes: Uint8Array) {
    this.writeU32LE(bytes.length)
    this.chunks.push(bytes)
  }

  writeString(str: string) {
    const enc = new TextEncoder()
    const bytes = enc.encode(str)
    this.writeU32LE(bytes.length)
    this.chunks.push(bytes)
  }

  concat(): Uint8Array {
    const total = this.chunks.reduce((s, c) => s + c.length, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const c of this.chunks) {
      out.set(c, offset)
      offset += c.length
    }
    return out
  }
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

export function fromHex(hex: string): Uint8Array {
  const n = hex.length
  if (n % 2 !== 0) throw new Error('hex length must be even')
  const out = new Uint8Array(n / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16)
  }
  return out
}

export function base64Encode(bytes: Uint8Array): string {
  if (typeof btoa !== 'undefined') {
    let binary = ''
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
    return btoa(binary)
  } else {
    // Node fallback if needed
    // @ts-ignore
    return Buffer.from(bytes).toString('base64')
  }
}
