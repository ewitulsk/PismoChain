import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { 
  buildCreateAccountPrehash, buildPhantomEnvelope, exampleSignerString, serializeCreateAccountTx, 
  serializeNewCoinTx, serializeMintTx, buildNewCoinPrehash, buildMintPrehash,
  SignatureType, SignerType, toBase64Borsh, deriveCoinAddr, deriveAccountAddr, deriveCoinStoreAddr, viewQuery
} from '../lib/pismo'
import { registerSlushWallet, SLUSH_WALLET_NAME } from '@mysten/slush-wallet'
import { getWallets } from '@wallet-standard/app'
import type { Wallet, WalletWithFeatures } from '@wallet-standard/core'
import type { SuiSignPersonalMessageFeature } from '@mysten/wallet-standard'
import type { StandardConnectFeature } from '@wallet-standard/core'
import { toByteArray as b64ToBytes } from 'base64-js'

function usePhantom() {
  const ready = typeof window !== 'undefined' && !!window.solana && window.solana?.isPhantom

  const connect = useCallback(async () => {
    if (!ready) throw new Error('Phantom not found')
    const res = await window.solana!.connect()
    return res
  }, [ready])

  const signMessage = useCallback(async (message: Uint8Array) => {
    if (!ready) throw new Error('Phantom not found')
    const { signature } = await window.solana!.signMessage(message, 'hex')
    return signature
  }, [ready])

  const pubkeyBase58 = window.solana?.publicKey?.toBase58()
  const pubkeyBytes = window.solana?.publicKey?.toBytes()

  return { ready, connect, signMessage, pubkeyBase58, pubkeyBytes }
}

function useSuiSlush() {
  const [wallet, setWallet] = useState<WalletWithFeatures<StandardConnectFeature & SuiSignPersonalMessageFeature> | null>(null)
  const [accountIdx, setAccountIdx] = useState<number | null>(null)

  const ready = !!wallet

  useEffect(() => {
    // Register Slush wallet once app is ready
    const reg = registerSlushWallet('Pismo DApp')
    // Discover wallets and pick Slush
    const { get } = getWallets()
    const w = get().find((w: Wallet) => w.name === SLUSH_WALLET_NAME)
    if (w && 'standard:connect' in w.features && 'sui:signPersonalMessage' in w.features) {
      setWallet(w as WalletWithFeatures<StandardConnectFeature & SuiSignPersonalMessageFeature>)
    }
    return () => {
      // Unregister if we registered
      try { reg?.unregister?.() } catch {}
    }
  }, [])

  const connect = useCallback(async () => {
    if (!wallet) throw new Error('Slush wallet not found')
    await wallet.features['standard:connect'].connect()
    if (!wallet.accounts.length) throw new Error('No Sui accounts')
    setAccountIdx(0)
    return wallet.accounts[0]
  }, [wallet])

  const signPersonalMessage = useCallback(async (message: Uint8Array) => {
    if (!wallet) throw new Error('Slush wallet not found')
    const idx = accountIdx ?? 0
    const account = wallet.accounts[idx]
    if (!account) throw new Error('No selected Sui account')
    const { signature } = await wallet.features['sui:signPersonalMessage'].signPersonalMessage({ message, account })
    return b64ToBytes(signature)
  }, [wallet, accountIdx])

  const pubkeyBytes = useMemo(() => {
    if (!wallet) return undefined
    const idx = accountIdx ?? 0
    return wallet.accounts[idx]?.publicKey as Uint8Array | undefined
  }, [wallet, accountIdx])

  const address = useMemo(() => {
    if (!wallet) return undefined
    const idx = accountIdx ?? 0
    return wallet.accounts[idx]?.address
  }, [wallet, accountIdx])

  return { ready, connect, signPersonalMessage, pubkeyBytes, address }
}



export default function App() {
  const { ready, connect, signMessage, pubkeyBase58, pubkeyBytes } = usePhantom()
  const { ready: suiReady, connect: suiConnect, signPersonalMessage: suiSignPersonalMessage, pubkeyBytes: suiPubkeyBytes, address: suiAddress } = useSuiSlush()
  const [status, setStatus] = useState<string>('')
  const [submitResult, setSubmitResult] = useState<any>(null)
  const [coinAddress, setCoinAddress] = useState<string>('')
  const [viewAddress, setViewAddress] = useState<string>('')
  const [viewType, setViewType] = useState<string>('Account')
  const [viewResult, setViewResult] = useState<any>(undefined)
  const [activeWalletType, setActiveWalletType] = useState<'phantom' | 'sui' | null>(null)
  const [currentNonce, setCurrentNonce] = useState<bigint>(BigInt(0))
  const [accountAddress, setAccountAddress] = useState<string>('')

  const signerStr = useMemo(() => pubkeyBase58 ? exampleSignerString(pubkeyBase58) : '', [pubkeyBase58])

  // Function to query and update current nonce
  const refreshNonce = useCallback(async () => {
    if (!activeWalletType) return

    try {
      let accountAddr: Uint8Array
      if (activeWalletType === 'phantom' && pubkeyBytes) {
        const publicKeyHex = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('')
        accountAddr = deriveAccountAddr(1, SignatureType.PhantomSolanaEd25519, publicKeyHex)
      } else if (activeWalletType === 'sui' && suiPubkeyBytes) {
        const publicKeyHex = Array.from(suiPubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('')
        accountAddr = deriveAccountAddr(1, SignatureType.SuiDev, publicKeyHex)
      } else {
        return
      }

      const hexAddr = Array.from(accountAddr).map(b => b.toString(16).padStart(2, '0')).join('')
      
      const accountData = await viewQuery(hexAddr, 'Account')
      if (accountData && accountData.current_nonce !== undefined) {
        setCurrentNonce(BigInt(accountData.current_nonce))
        console.log('Updated nonce to:', accountData.current_nonce)
      }
    } catch (e) {
      console.warn('Could not refresh nonce:', e)
      // Keep current nonce if query fails
    }
  }, [activeWalletType, pubkeyBytes, suiPubkeyBytes])

  const onConnect = useCallback(async () => {
    setStatus('Connecting...')
    try {
      await connect()
      setActiveWalletType('phantom')
      setStatus('Phantom wallet connected')
      // Try to refresh nonce after a short delay
      setTimeout(() => refreshNonce(), 500)
    } catch (e: any) {
      setStatus(`Connect error: ${e?.message || e}`)
    }
  }, [connect, refreshNonce])

  const onCreateAccount = useCallback(async () => {
    try {
      if (!pubkeyBytes) throw new Error('Connect Phantom first')

      const publicKeyHex = Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('')
      const createdAtMs = 0n
      const nonce = 0n
      const chainId = 2

      // Derive the account address that will be created
      const accountAddr = deriveAccountAddr(1, SignatureType.PhantomSolanaEd25519, publicKeyHex)
      const accountAddrHex = Array.from(accountAddr).map(b => b.toString(16).padStart(2, '0')).join('')

      // Build hash preimage per backend formula and hash
      const hash = buildCreateAccountPrehash(publicKeyHex, signerStr, createdAtMs, nonce, chainId)

      // Build Phantom envelope and sign its UTF-8 bytes
      const envelope = buildPhantomEnvelope({
        app: 'example.com',
        purpose: 'session-key binding',
        dataBytes: hash,
        nonce,
      })
      setStatus('Requesting signature in Phantom...')
      const signature = await signMessage(new TextEncoder().encode(envelope))

      // Construct final Borsh tx
      const txBytes = serializeCreateAccountTx({
        publicKeyHex,
        signer: signerStr,
        createdAtMs,
        nonce,
        chainId,
        signatureType: SignatureType.PhantomSolanaEd25519,
        signerType: SignerType.NewAccount,
        signatureBytes: signature,
        hashBytes: hash,
      })

      const base64Tx = toBase64Borsh(txBytes)

      // Submit to backend through proxy
      setStatus('Submitting to node...')
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'submit_borsh_tx',
          params: [base64Tx],
        }),
      })

      const json = await res.json().catch(() => ({}))
      setSubmitResult(json)
      if (res.ok) {
        setAccountAddress(accountAddrHex)
        setStatus('Account created successfully')
        // Wait a moment for the transaction to be processed, then refresh nonce
        setTimeout(() => refreshNonce(), 1000)
      } else {
        setStatus(`Submit error: HTTP ${res.status}`)
      }
    } catch (e: any) {
      console.error(e)
      setStatus(`Error: ${e?.message || e}`)
    }
  }, [pubkeyBytes, signerStr, signMessage, refreshNonce])

  const suiSignerStr = useMemo(() => (suiAddress ? `sui:${suiAddress}` : ''), [suiAddress])

  // Wallet-agnostic helper to get current wallet info - only use explicitly selected wallet
  const currentWallet = useMemo(() => {
    if (activeWalletType === 'phantom' && pubkeyBytes && pubkeyBase58) {
      return {
        type: 'phantom' as const,
        publicKeyHex: Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
        signer: signerStr,
        signatureType: SignatureType.PhantomSolanaEd25519,
        signerType: SignerType.Linked,
        signMessage: signMessage,
      }
    } else if (activeWalletType === 'sui' && suiPubkeyBytes && suiAddress) {
      return {
        type: 'sui' as const,
        publicKeyHex: Array.from(suiPubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
        signer: suiSignerStr,
        signatureType: SignatureType.SuiDev,
        signerType: SignerType.Linked,
        signMessage: suiSignPersonalMessage,
      }
    }
    return null
  }, [activeWalletType, pubkeyBytes, pubkeyBase58, signerStr, signMessage, suiPubkeyBytes, suiAddress, suiSignerStr, suiSignPersonalMessage])

  const onConnectSui = useCallback(async () => {
    setStatus('Connecting Sui (Slush)...')
    try {
      await suiConnect()
      setActiveWalletType('sui')
      setStatus('Slush wallet connected')
      // Try to refresh nonce after a short delay
      setTimeout(() => refreshNonce(), 500)
    } catch (e: any) {
      setStatus(`Sui connect error: ${e?.message || e}`)
    }
  }, [suiConnect, refreshNonce])

  const onCreateAccountSui = useCallback(async () => {
    try {
      if (!suiPubkeyBytes) throw new Error('Connect Sui first')

      const publicKeyHex = Array.from(suiPubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('')
      const createdAtMs = 0n
      const nonce = 0n
      const chainId = 2

      // Derive the account address that will be created
      const accountAddr = deriveAccountAddr(1, SignatureType.SuiDev, publicKeyHex)
      const accountAddrHex = Array.from(accountAddr).map(b => b.toString(16).padStart(2, '0')).join('')

      const hash = buildCreateAccountPrehash(publicKeyHex, suiSignerStr, createdAtMs, nonce, chainId)

      // Reuse same textual envelope pattern
      const envelope = buildPhantomEnvelope({
        app: 'example.com',
        purpose: 'session-key binding',
        dataBytes: hash,
        nonce,
      })
      setStatus('Requesting signature in Slush...')
      const signatureBytes = await suiSignPersonalMessage(new TextEncoder().encode(envelope))

      const txBytes = serializeCreateAccountTx({
        publicKeyHex,
        signer: suiSignerStr,
        createdAtMs,
        nonce,
        chainId,
        signatureType: SignatureType.SuiDev,
        signerType: SignerType.NewAccount,
        signatureBytes,
        hashBytes: hash,
      })

      const base64Tx = toBase64Borsh(txBytes)

      setStatus('Submitting to node...')
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'submit_borsh_tx',
          params: [base64Tx],
        }),
      })

      const json = await res.json().catch(() => ({}))
      setSubmitResult(json)
      if (res.ok) {
        setAccountAddress(accountAddrHex)
        setStatus('Account created successfully')
        // Wait a moment for the transaction to be processed, then refresh nonce
        setTimeout(() => refreshNonce(), 1000)
      } else {
        setStatus(`Submit error: HTTP ${res.status}`)
      }
    } catch (e: any) {
      console.error(e)
      setStatus(`Error: ${e?.message || e}`)
    }
  }, [suiPubkeyBytes, suiSignerStr, suiSignPersonalMessage, refreshNonce])

  const onCreateCoin = useCallback(async () => {
    try {
      if (!currentWallet) throw new Error('Connect a wallet first')

      // Coin parameters
      const name = 'TestCoin'
      const projectUri = 'https://testcoin.com'
      const logoUri = 'https://testcoin.com/logo.png'
      const totalSupply = BigInt(0) // Initialize with zero total supply
      const maxSupply = BigInt(10000000)
      const canonicalChainId = BigInt(4206980085)
      const nonce = currentNonce // Use actual current nonce
      const chainId = 2

      // Derive the coin address for display
      const seedAddr = deriveAccountAddr(1, currentWallet.signatureType, currentWallet.publicKeyHex)
      const coinAddr = deriveCoinAddr(seedAddr, name, canonicalChainId)
      setCoinAddress(Array.from(coinAddr).map(b => b.toString(16).padStart(2, '0')).join(''))

      // Build hash
      const hash = buildNewCoinPrehash(
        currentWallet.publicKeyHex,
        currentWallet.signer,
        name,
        projectUri,
        logoUri,
        totalSupply,
        maxSupply,
        canonicalChainId,
        nonce,
        chainId
      )

      // Build envelope and sign
      const envelope = buildPhantomEnvelope({
        app: 'example.com',
        purpose: 'session-key binding',
        dataBytes: hash,
        nonce,
      })
      
      setStatus('Requesting signature...')
      const signature = await currentWallet.signMessage(new TextEncoder().encode(envelope))

      // Serialize transaction
      const txBytes = serializeNewCoinTx({
        publicKeyHex: currentWallet.publicKeyHex,
        signer: currentWallet.signer,
        name,
        projectUri,
        logoUri,
        totalSupply,
        maxSupply,
        canonicalChainId,
        nonce,
        chainId,
        signatureType: currentWallet.signatureType,
        signerType: currentWallet.signerType,
        signatureBytes: signature,
        hashBytes: hash,
      })

      const base64Tx = toBase64Borsh(txBytes)

      // Submit to backend
      setStatus('Submitting NewCoin transaction...')
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'submit_borsh_tx',
          params: [base64Tx],
        }),
      })

      const json = await res.json().catch(() => ({}))
      setSubmitResult(json)
      if (res.ok) {
        setStatus('NewCoin transaction submitted')
        // Wait a moment for the transaction to be processed, then refresh nonce
        setTimeout(() => refreshNonce(), 1000)
      } else {
        setStatus(`Submit error: HTTP ${res.status}`)
      }
    } catch (e: any) {
      console.error(e)
      setStatus(`Error: ${e?.message || e}`)
    }
  }, [currentWallet, currentNonce, refreshNonce])

  const onMint = useCallback(async () => {
    try {
      if (!currentWallet) throw new Error('Connect a wallet first')
      if (!coinAddress) throw new Error('Create a coin first to get coin address')

      // Convert hex coin address back to bytes
      const coinAddrBytes = new Uint8Array(coinAddress.match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
      
      // Use the current wallet's account address as the mint target
      const accountAddr = deriveAccountAddr(1, currentWallet.signatureType, currentWallet.publicKeyHex)
      const amount = BigInt(100000) // Mint 100,000 tokens
      const nonce = currentNonce // Use actual current nonce
      const chainId = 2

      // Build hash
      const hash = buildMintPrehash(
        currentWallet.publicKeyHex,
        currentWallet.signer,
        coinAddrBytes,
        accountAddr,
        amount,
        nonce,
        chainId
      )

      // Build envelope and sign
      const envelope = buildPhantomEnvelope({
        app: 'example.com',
        purpose: 'session-key binding',
        dataBytes: hash,
        nonce,
      })
      
      setStatus('Requesting signature...')
      const signature = await currentWallet.signMessage(new TextEncoder().encode(envelope))

      // Serialize transaction
      const txBytes = serializeMintTx({
        publicKeyHex: currentWallet.publicKeyHex,
        signer: currentWallet.signer,
        coinAddr: coinAddrBytes,
        accountAddr,
        amount,
        nonce,
        chainId,
        signatureType: currentWallet.signatureType,
        signerType: currentWallet.signerType,
        signatureBytes: signature,
        hashBytes: hash,
      })

      const base64Tx = toBase64Borsh(txBytes)

      // Submit to backend
      setStatus('Submitting Mint transaction...')
      const res = await fetch('/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'submit_borsh_tx',
          params: [base64Tx],
        }),
      })

      const json = await res.json().catch(() => ({}))
      setSubmitResult(json)
      if (res.ok) {
        setStatus('Mint transaction submitted')
        // Wait a moment for the transaction to be processed, then refresh nonce
        setTimeout(() => refreshNonce(), 1000)
      } else {
        setStatus(`Submit error: HTTP ${res.status}`)
      }
    } catch (e: any) {
      console.error(e)
      setStatus(`Error: ${e?.message || e}`)
    }
  }, [currentWallet, coinAddress, currentNonce, refreshNonce])

  const onDisconnectWallet = useCallback(() => {
    setActiveWalletType(null)
    setCoinAddress('')
    setAccountAddress('')
    setCurrentNonce(BigInt(0))
    setStatus('Wallet disconnected')
  }, [])



  const onViewQuery = useCallback(async () => {
    try {
      if (!viewAddress.trim()) throw new Error('Enter an address to query')
      
      setStatus('Querying state...')
      
      let result
      if (viewType === 'Link') {
        // For Link queries, we need to pass signature_type and external_address
        if (!currentWallet) {
          throw new Error('Connect a wallet to query links')
        }
        
        result = await viewQuery(viewAddress.trim(), viewType, {
          signature_type: currentWallet.signatureType,
          external_address: viewAddress.trim()
        })
      } else {
        result = await viewQuery(viewAddress.trim(), viewType)
      }
      
      console.log('View query result:', result)
      setViewResult(result)
      setStatus(`Query completed - ${result === null ? 'Object not found' : 'Object found'}`)
    } catch (e: any) {
      console.error(e)
      setStatus(`Query error: ${e?.message || e}`)
      setViewResult(undefined)
    }
  }, [viewAddress, viewType, currentWallet])

  // Helper to populate view address with useful addresses
  const populateAccountAddress = useCallback(() => {
    if (accountAddress) {
      setViewAddress(accountAddress)
      setViewType('Account')
    } else if (currentWallet) {
      const accountAddr = deriveAccountAddr(1, currentWallet.signatureType, currentWallet.publicKeyHex)
      const hexAddr = Array.from(accountAddr).map(b => b.toString(16).padStart(2, '0')).join('')
      setViewAddress(hexAddr)
      setViewType('Account')
    }
  }, [currentWallet, accountAddress])

  const populateCoinStoreAddress = useCallback(() => {
    if (coinAddress && (accountAddress || currentWallet)) {
      let accountAddr: Uint8Array
      if (accountAddress) {
        accountAddr = new Uint8Array(accountAddress.match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
      } else if (currentWallet) {
        accountAddr = deriveAccountAddr(1, currentWallet.signatureType, currentWallet.publicKeyHex)
      } else {
        return
      }
      
      const coinAddrBytes = new Uint8Array(coinAddress.match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
      const storeAddr = deriveCoinStoreAddr(accountAddr, coinAddrBytes)
      const hexAddr = Array.from(storeAddr).map(b => b.toString(16).padStart(2, '0')).join('')
      setViewAddress(hexAddr)
      setViewType('CoinStore')
    }
  }, [currentWallet, coinAddress, accountAddress])

  const populateLinkAddress = useCallback(() => {
    if (currentWallet) {
      // For Link queries, we use the external wallet address (public key hex)
      setViewAddress(currentWallet.publicKeyHex)
      setViewType('Link')
    }
  }, [currentWallet])

  return (
    <div style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: 24, lineHeight: 1.5, maxWidth: 720 }}>
      <h2>Pismo CreateAccount via Phantom</h2>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <button onClick={onConnect} disabled={!ready}>
          {ready ? 'Connect Phantom' : 'Install Phantom'}
        </button>
        {pubkeyBase58 && <code>{pubkeyBase58}</code>}
      </div>

      <div style={{ marginTop: 16 }}>
        <button onClick={onCreateAccount} disabled={!pubkeyBytes}>Sign & Submit CreateAccount</button>
      </div>

      <hr style={{ margin: '24px 0' }} />

      <h2>Pismo CreateAccount via Sui (Slush)</h2>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <button onClick={onConnectSui} disabled={!suiReady}>
          {suiReady ? 'Connect Slush' : 'Install Slush'}
        </button>
        {suiAddress && <code>{suiAddress}</code>}
      </div>

      <div style={{ marginTop: 16 }}>
        <button onClick={onCreateAccountSui} disabled={!suiPubkeyBytes}>Sign & Submit CreateAccount (Sui)</button>
      </div>

      <hr style={{ margin: '24px 0' }} />

      <h2>Wallet-Agnostic Token Operations</h2>
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div><strong>Active Wallet:</strong> {currentWallet ? `${currentWallet.type} (${currentWallet.signer})` : 'None'}</div>
          {currentWallet && (
            <button onClick={onDisconnectWallet} style={{ padding: '4px 8px', fontSize: '12px' }}>
              Switch Wallet
            </button>
          )}
        </div>
        {currentWallet && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '14px' }}>
            <div><strong>Current Nonce:</strong> {currentNonce.toString()}</div>
            <button onClick={refreshNonce} style={{ padding: '4px 8px', fontSize: '12px' }}>
              Refresh Nonce
            </button>
          </div>
        )}
      </div>

      {accountAddress && (
        <div style={{ marginBottom: 16 }}>
          <div><strong>Account Address:</strong></div>
          <code style={{ display: 'block', background: '#f6f8fa', padding: 8, borderRadius: 4, fontSize: '12px', wordBreak: 'break-all' }}>
            {accountAddress}
          </code>
        </div>
      )}

      {!currentWallet && (
        <div style={{ padding: 16, background: '#f0f8ff', borderRadius: 8, marginBottom: 16, textAlign: 'center' }}>
          <div style={{ marginBottom: 8 }}><strong>Select a wallet to use token operations:</strong></div>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
            <button onClick={onConnect} disabled={!ready} style={{ padding: '8px 16px' }}>
              Use Phantom
            </button>
            <button onClick={onConnectSui} disabled={!suiReady} style={{ padding: '8px 16px' }}>
              Use Slush
            </button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={onCreateCoin} disabled={!currentWallet}>
          Create New Coin
        </button>
        <button onClick={onMint} disabled={!currentWallet || !coinAddress}>
          Mint Tokens
        </button>
      </div>

      {coinAddress && (
        <div style={{ marginBottom: 16 }}>
          <div><strong>Coin Address:</strong></div>
          <code style={{ display: 'block', background: '#f6f8fa', padding: 8, borderRadius: 4, fontSize: '12px', wordBreak: 'break-all' }}>
            {coinAddress}
          </code>
        </div>
      )}

      <hr style={{ margin: '24px 0' }} />

      <h2>State Viewer</h2>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
        <input
          type="text"
          placeholder="Enter address (hex)"
          value={viewAddress}
          onChange={(e) => setViewAddress(e.target.value)}
          style={{ flex: 1, padding: 8, border: '1px solid #ccc', borderRadius: 4 }}
        />
        <select
          value={viewType}
          onChange={(e) => setViewType(e.target.value)}
          style={{ padding: 8, border: '1px solid #ccc', borderRadius: 4 }}
        >
          <option value="Account">Account</option>
          <option value="Coin">Coin</option>
          <option value="CoinStore">CoinStore</option>
          <option value="Link">Link</option>
        </select>
        <button onClick={onViewQuery}>Query</button>
      </div>
      
      <div style={{ display: 'flex', gap: 8, marginBottom: 16, fontSize: '14px' }}>
        <button onClick={populateAccountAddress} disabled={!currentWallet} style={{ padding: '4px 8px' }}>
          My Account
        </button>
        <button onClick={() => { setViewAddress(coinAddress); setViewType('Coin') }} disabled={!coinAddress} style={{ padding: '4px 8px' }}>
          My Coin
        </button>
        <button onClick={populateCoinStoreAddress} disabled={!currentWallet || !coinAddress} style={{ padding: '4px 8px' }}>
          My CoinStore
        </button>
        <button onClick={populateLinkAddress} disabled={!currentWallet} style={{ padding: '4px 8px' }}>
          My Link
        </button>
      </div>

      {viewResult !== undefined && (
        <div style={{ marginBottom: 16 }}>
          <div><strong>Query Result:</strong></div>
          <pre style={{ background: '#f6f8fa', padding: 12, borderRadius: 6, overflowX: 'auto', fontSize: '12px' }}>
{viewResult === null ? 'Object not found (null)' : JSON.stringify(viewResult, null, 2)}
          </pre>
        </div>
      )}

      <div style={{ marginTop: 16 }}>
        <div><strong>Status:</strong> {status}</div>
      </div>

      {submitResult && (
        <pre style={{ marginTop: 16, background: '#f6f8fa', padding: 12, borderRadius: 6, overflowX: 'auto' }}>
{JSON.stringify(submitResult, null, 2)}
        </pre>
      )}

      {!ready && (
        <p>
          Phantom not detected. Install from{' '}
          <a href="https://phantom.app/" target="_blank" rel="noreferrer">phantom.app</a> and refresh.
        </p>
      )}

      {!suiReady && (
        <p>
          Slush not detected. Learn more at{' '}
          <a href="https://sdk.mystenlabs.com/slush-wallet/dapp" target="_blank" rel="noreferrer">Slush Wallet</a>.
        </p>
      )}
    </div>
  )
}
