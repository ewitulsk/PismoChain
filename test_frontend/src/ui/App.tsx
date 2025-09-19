import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { 
  buildCreateAccountPrehash, buildPhantomEnvelope, exampleSignerString, serializeCreateAccountTx, 
  serializeNewCoinTx, serializeMintTx, serializeTransferTx, serializeCreateOrderbookTx, serializeNewLimitOrderTx,
  buildNewCoinPrehash, buildMintPrehash, buildTransferPrehash, buildCreateOrderbookPrehash, buildNewLimitOrderPrehash,
  SignatureType, SignerType, toBase64Borsh, deriveCoinAddr, deriveAccountAddr, deriveCoinStoreAddr, deriveOrderbookAddr, viewQuery
} from '../lib/pismo'
import OrderbookVisualizer from './OrderbookVisualizer'
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
  const [transferReceiverAddress, setTransferReceiverAddress] = useState<string>('')
  const [transferAmount, setTransferAmount] = useState<string>('1000')
  const [transferCoinAddress, setTransferCoinAddress] = useState<string>('')
  const [lastTransferReceiverCoinStore, setLastTransferReceiverCoinStore] = useState<string>('')
  
  // Orderbook state
  const [orderbookBuyAsset, setOrderbookBuyAsset] = useState<string>('')
  const [orderbookSellAsset, setOrderbookSellAsset] = useState<string>('')
  const [createdOrderbookAddress, setCreatedOrderbookAddress] = useState<string>('')
  
  // Limit order state
  const [limitOrderOrderbookAddress, setLimitOrderOrderbookAddress] = useState<string>('')
  const [limitOrderIsBuy, setLimitOrderIsBuy] = useState<boolean>(true)
  const [limitOrderAmount, setLimitOrderAmount] = useState<string>('1000')
  const [limitOrderTickPrice, setLimitOrderTickPrice] = useState<string>('100')
  
  // Token management state
  const [tokenAddresses, setTokenAddresses] = useState<string[]>([])
  const [newTokenAddress, setNewTokenAddress] = useState<string>('')
  const [tokenBalances, setTokenBalances] = useState<Record<string, { balance: string | null, coinStoreAddress: string }>>({})
  const [isQueryingBalances, setIsQueryingBalances] = useState<boolean>(false)

  // Node endpoint configuration
  const [nodeEndpoint, setNodeEndpoint] = useState<string>('http://127.0.0.1:9944')
  const [isTestingConnection, setIsTestingConnection] = useState<boolean>(false)
  const [nodeStatus, setNodeStatus] = useState<'unknown' | 'connected' | 'error'>('unknown')

  const signerStr = useMemo(() => pubkeyBase58 ? exampleSignerString(pubkeyBase58) : '', [pubkeyBase58])

  // Helper function to make RPC calls with configurable endpoint
  const makeRpcCall = useCallback(async (method: string, params: any) => {
    const endpoint = nodeEndpoint.endsWith('/') ? nodeEndpoint.slice(0, -1) : nodeEndpoint
    const url = endpoint.startsWith('http') ? endpoint : `http://${endpoint}`
    
    // Use the Vite proxy for ALL 127.0.0.1 connections to avoid CORS issues
    const isLocalhost = url.includes('127.0.0.1') || url.includes('localhost')
    const fetchUrl = isLocalhost ? '/rpc' : url
    
    // Log the URL being called for debugging
    console.log(`🌐 Blockchain RPC Call: ${method} -> ${fetchUrl}${isLocalhost ? ` (proxying to ${url})` : ''}`)
    
    const response = await fetch(fetchUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method,
        params,
      }),
    })
    
    return response
  }, [nodeEndpoint])

  // Test connection to the selected node
  const testNodeConnection = useCallback(async () => {
    setIsTestingConnection(true)
    try {
      const response = await makeRpcCall('view', { address: '0000000000000000000000000000000000000000000000000000000000000000', type: 'Account' })
      if (response.ok) {
        setNodeStatus('connected')
        setStatus(`Connected to node: ${nodeEndpoint}`)
      } else {
        setNodeStatus('error')
        setStatus(`Failed to connect to node: HTTP ${response.status}`)
      }
    } catch (e: any) {
      setNodeStatus('error')
      setStatus(`Connection error: ${e?.message || e}`)
    } finally {
      setIsTestingConnection(false)
    }
  }, [makeRpcCall, nodeEndpoint])

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
      
      const response = await makeRpcCall('view', { address: hexAddr, type: 'Account' })
      if (response.ok) {
        const json = await response.json()
        const accountData = json.result
        if (accountData && accountData.current_nonce !== undefined) {
          setCurrentNonce(BigInt(accountData.current_nonce))
          console.log('Updated nonce to:', accountData.current_nonce)
        }
      }
    } catch (e) {
      console.warn('Could not refresh nonce:', e)
      // Keep current nonce if query fails
    }
  }, [activeWalletType, pubkeyBytes, suiPubkeyBytes, makeRpcCall])

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
      const res = await makeRpcCall('submit_borsh_tx', [base64Tx])

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
  }, [pubkeyBytes, signerStr, signMessage, refreshNonce, makeRpcCall])

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
      const res = await makeRpcCall('submit_borsh_tx', [base64Tx])

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
  }, [suiPubkeyBytes, suiSignerStr, suiSignPersonalMessage, refreshNonce, makeRpcCall])

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
      const res = await makeRpcCall('submit_borsh_tx', [base64Tx])

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
  }, [currentWallet, currentNonce, refreshNonce, makeRpcCall])

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
      const res = await makeRpcCall('submit_borsh_tx', [base64Tx])

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
  }, [currentWallet, coinAddress, currentNonce, refreshNonce, makeRpcCall])

  const onTransfer = useCallback(async () => {
    try {
      if (!currentWallet) throw new Error('Connect a wallet first')
      if (!transferCoinAddress.trim()) throw new Error('Enter coin address')
      if (!transferReceiverAddress.trim()) throw new Error('Enter receiver address')

      // Convert hex coin address back to bytes
      let coinAddrBytes: Uint8Array
      try {
        coinAddrBytes = new Uint8Array(transferCoinAddress.trim().match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
        if (coinAddrBytes.length !== 32) {
          throw new Error('Coin address must be exactly 32 bytes (64 hex characters)')
        }
      } catch (e) {
        throw new Error('Invalid coin address format. Must be a 64-character hex string.')
      }
      
      // Convert hex receiver address to bytes
      let receiverAddrBytes: Uint8Array
      try {
        receiverAddrBytes = new Uint8Array(transferReceiverAddress.trim().match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
        if (receiverAddrBytes.length !== 32) {
          throw new Error('Receiver address must be exactly 32 bytes (64 hex characters)')
        }
      } catch (e) {
        throw new Error('Invalid receiver address format. Must be a 64-character hex string.')
      }
      
      const amount = BigInt(transferAmount) // Transfer amount from input
      const nonce = currentNonce // Use actual current nonce
      const chainId = 2

      // Build hash
      const hash = buildTransferPrehash(
        currentWallet.publicKeyHex,
        currentWallet.signer,
        coinAddrBytes,
        receiverAddrBytes,
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
      const txBytes = serializeTransferTx({
        publicKeyHex: currentWallet.publicKeyHex,
        signer: currentWallet.signer,
        coinAddr: coinAddrBytes,
        receiverAddr: receiverAddrBytes,
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
      setStatus('Submitting Transfer transaction...')
      const res = await makeRpcCall('submit_borsh_tx', [base64Tx])

      const json = await res.json().catch(() => ({}))
      setSubmitResult(json)
      if (res.ok) {
        // Calculate and store the receiver's coinstore address
        const receiverCoinStoreAddr = deriveCoinStoreAddr(receiverAddrBytes, coinAddrBytes)
        const receiverCoinStoreHex = Array.from(receiverCoinStoreAddr).map(b => b.toString(16).padStart(2, '0')).join('')
        setLastTransferReceiverCoinStore(receiverCoinStoreHex)
        
        setStatus('Transfer transaction submitted')
        // Wait a moment for the transaction to be processed, then refresh nonce
        setTimeout(() => refreshNonce(), 1000)
      } else {
        setStatus(`Submit error: HTTP ${res.status}`)
      }
    } catch (e: any) {
      console.error(e)
      setStatus(`Error: ${e?.message || e}`)
    }
  }, [currentWallet, transferCoinAddress, transferReceiverAddress, transferAmount, currentNonce, refreshNonce, makeRpcCall])

  const onCreateOrderbook = useCallback(async () => {
    try {
      if (!currentWallet) throw new Error('Connect a wallet first')
      if (!orderbookBuyAsset.trim()) throw new Error('Enter buy asset address')
      if (!orderbookSellAsset.trim()) throw new Error('Enter sell asset address')

      // Validate hex addresses
      if (orderbookBuyAsset.trim().length !== 64) throw new Error('Buy asset address must be 64 hex characters')
      if (orderbookSellAsset.trim().length !== 64) throw new Error('Sell asset address must be 64 hex characters')

      const nonce = currentNonce
      const chainId = 2

      // Build hash
      const hash = buildCreateOrderbookPrehash(
        currentWallet.publicKeyHex,
        currentWallet.signer,
        orderbookBuyAsset.trim(),
        orderbookSellAsset.trim(),
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
      const txBytes = serializeCreateOrderbookTx({
        publicKeyHex: currentWallet.publicKeyHex,
        signer: currentWallet.signer,
        buyAsset: orderbookBuyAsset.trim(),
        sellAsset: orderbookSellAsset.trim(),
        nonce,
        chainId,
        signatureType: currentWallet.signatureType,
        signerType: currentWallet.signerType,
        signatureBytes: signature,
        hashBytes: hash,
      })

      const base64Tx = toBase64Borsh(txBytes)

      // Submit to backend
      setStatus('Submitting CreateOrderbook transaction...')
      const res = await makeRpcCall('submit_borsh_tx', [base64Tx])

      const json = await res.json().catch(() => ({}))
      setSubmitResult(json)
      if (res.ok) {
        // Calculate and store the orderbook address
        const buyAssetBytes = new Uint8Array(orderbookBuyAsset.trim().match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
        const sellAssetBytes = new Uint8Array(orderbookSellAsset.trim().match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
        const orderbookAddr = deriveOrderbookAddr(buyAssetBytes, sellAssetBytes)
        const orderbookAddrHex = Array.from(orderbookAddr).map(b => b.toString(16).padStart(2, '0')).join('')
        setCreatedOrderbookAddress(orderbookAddrHex)
        
        setStatus('CreateOrderbook transaction submitted')
        // Wait a moment for the transaction to be processed, then refresh nonce
        setTimeout(() => refreshNonce(), 1000)
      } else {
        setStatus(`Submit error: HTTP ${res.status}`)
      }
    } catch (e: any) {
      console.error(e)
      setStatus(`Error: ${e?.message || e}`)
    }
  }, [currentWallet, orderbookBuyAsset, orderbookSellAsset, currentNonce, refreshNonce, makeRpcCall])

  const onPlaceLimitOrder = useCallback(async () => {
    try {
      if (!currentWallet) throw new Error('Connect a wallet first')
      if (!limitOrderOrderbookAddress.trim()) throw new Error('Enter orderbook address')
      if (!limitOrderAmount.trim()) throw new Error('Enter order amount')
      if (!limitOrderTickPrice.trim()) throw new Error('Enter tick price')

      // Validate orderbook address
      if (limitOrderOrderbookAddress.trim().length !== 64) throw new Error('Orderbook address must be 64 hex characters')

      // Convert hex orderbook address to bytes
      const orderbookAddrBytes = new Uint8Array(limitOrderOrderbookAddress.trim().match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
      
      const amount = BigInt(limitOrderAmount)
      const tickPrice = BigInt(limitOrderTickPrice)
      const nonce = currentNonce
      const chainId = 2

      // Build hash
      const hash = buildNewLimitOrderPrehash(
        currentWallet.publicKeyHex,
        currentWallet.signer,
        orderbookAddrBytes,
        limitOrderIsBuy,
        amount,
        tickPrice,
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
      const txBytes = serializeNewLimitOrderTx({
        publicKeyHex: currentWallet.publicKeyHex,
        signer: currentWallet.signer,
        orderbookAddress: orderbookAddrBytes,
        isBuy: limitOrderIsBuy,
        amount,
        tickPrice,
        nonce,
        chainId,
        signatureType: currentWallet.signatureType,
        signerType: currentWallet.signerType,
        signatureBytes: signature,
        hashBytes: hash,
      })

      const base64Tx = toBase64Borsh(txBytes)

      // Submit to backend
      setStatus('Submitting NewLimitOrder transaction...')
      const res = await makeRpcCall('submit_borsh_tx', [base64Tx])

      const json = await res.json().catch(() => ({}))
      setSubmitResult(json)
      if (res.ok) {
        setStatus(`${limitOrderIsBuy ? 'BUY' : 'SELL'} limit order submitted`)
        // Wait a moment for the transaction to be processed, then refresh nonce
        setTimeout(() => refreshNonce(), 1000)
      } else {
        setStatus(`Submit error: HTTP ${res.status}`)
      }
    } catch (e: any) {
      console.error(e)
      setStatus(`Error: ${e?.message || e}`)
    }
  }, [currentWallet, limitOrderOrderbookAddress, limitOrderIsBuy, limitOrderAmount, limitOrderTickPrice, currentNonce, refreshNonce, makeRpcCall])

  const onDisconnectWallet = useCallback(() => {
    setActiveWalletType(null)
    setCoinAddress('')
    setAccountAddress('')
    setCurrentNonce(BigInt(0))
    setTransferReceiverAddress('')
    setTransferCoinAddress('')
    setLastTransferReceiverCoinStore('')
    // Clear orderbook state
    setOrderbookBuyAsset('')
    setOrderbookSellAsset('')
    setCreatedOrderbookAddress('')
    setLimitOrderOrderbookAddress('')
    // Clear token management state
    setTokenAddresses([])
    setNewTokenAddress('')
    setTokenBalances({})
    setStatus('Wallet disconnected')
  }, [])

  // Token management functions
  const addTokenAddress = useCallback(() => {
    if (!newTokenAddress.trim()) return
    
    // Validate hex address format
    if (newTokenAddress.trim().length !== 64) {
      setStatus('Token address must be 64 hex characters')
      return
    }
    
    // Check if already added
    if (tokenAddresses.includes(newTokenAddress.trim())) {
      setStatus('Token address already added')
      return
    }
    
    setTokenAddresses(prev => [...prev, newTokenAddress.trim()])
    setNewTokenAddress('')
    setStatus('Token address added')
  }, [newTokenAddress, tokenAddresses])

  const removeTokenAddress = useCallback((addressToRemove: string) => {
    setTokenAddresses(prev => prev.filter(addr => addr !== addressToRemove))
    setTokenBalances(prev => {
      const newBalances = { ...prev }
      delete newBalances[addressToRemove]
      return newBalances
    })
    setStatus('Token address removed')
  }, [])

  const queryAllBalances = useCallback(async () => {
    if (!currentWallet) {
      setStatus('Connect a wallet first')
      return
    }
    
    if (tokenAddresses.length === 0) {
      setStatus('No token addresses added')
      return
    }

    setIsQueryingBalances(true)
    setStatus('Querying token balances...')
    
    try {
      // Derive user's account address
      const accountAddr = deriveAccountAddr(1, currentWallet.signatureType, currentWallet.publicKeyHex)
      
      const balanceResults: Record<string, { balance: string | null, coinStoreAddress: string }> = {}
      
      // Query each token's coinstore
      for (const tokenAddr of tokenAddresses) {
        try {
          const coinAddrBytes = new Uint8Array(tokenAddr.match(/.{2}/g)!.map(hex => parseInt(hex, 16)))
          const coinStoreAddr = deriveCoinStoreAddr(accountAddr, coinAddrBytes)
          const coinStoreHex = Array.from(coinStoreAddr).map(b => b.toString(16).padStart(2, '0')).join('')
          
          // Query the coinstore
          const response = await makeRpcCall('view', { address: coinStoreHex, type: 'CoinStore' })
          const result = response.ok ? (await response.json()).result : null
          
          balanceResults[tokenAddr] = {
            balance: result?.amount?.toString() ?? null, // null means coinstore doesn't exist (0 balance)
            coinStoreAddress: coinStoreHex
          }
        } catch (e) {
          console.warn(`Failed to query balance for token ${tokenAddr}:`, e)
          balanceResults[tokenAddr] = {
            balance: null, // Treat as 0 balance
            coinStoreAddress: 'unknown'
          }
        }
      }
      
      setTokenBalances(balanceResults)
      setStatus(`Queried balances for ${tokenAddresses.length} tokens`)
    } catch (e: any) {
      console.error('Failed to query balances:', e)
      setStatus(`Error querying balances: ${e?.message || e}`)
    } finally {
      setIsQueryingBalances(false)
    }
  }, [currentWallet, tokenAddresses, makeRpcCall])



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
        
        const response = await makeRpcCall('view', {
          address: viewAddress.trim(),
          type: viewType,
          signature_type: currentWallet.signatureType,
          external_address: viewAddress.trim()
        })
        result = response.ok ? (await response.json()).result : null
      } else {
        const response = await makeRpcCall('view', { address: viewAddress.trim(), type: viewType })
        result = response.ok ? (await response.json()).result : null
      }
      
      console.log('View query result:', result)
      setViewResult(result)
      setStatus(`Query completed - ${result === null ? 'Object not found' : 'Object found'}`)
    } catch (e: any) {
      console.error(e)
      setStatus(`Query error: ${e?.message || e}`)
      setViewResult(undefined)
    }
  }, [viewAddress, viewType, currentWallet, makeRpcCall])

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

  const populateReceiverWithMyAccount = useCallback(() => {
    if (currentWallet) {
      const accountAddr = deriveAccountAddr(1, currentWallet.signatureType, currentWallet.publicKeyHex)
      const hexAddr = Array.from(accountAddr).map(b => b.toString(16).padStart(2, '0')).join('')
      setTransferReceiverAddress(hexAddr)
    }
  }, [currentWallet])

  return (
    <div style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: 24, lineHeight: 1.5, maxWidth: 720 }}>
      {/* Node Configuration Section */}
      <div style={{ marginBottom: 24, padding: 16, border: '1px solid #e1e5e9', borderRadius: 8, background: '#f8f9fa' }}>
        <h3 style={{ margin: '0 0 16px 0', fontSize: '16px' }}>Blockchain Node Configuration</h3>
        
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
          <label style={{ minWidth: '120px', fontSize: '14px' }}>Node Endpoint:</label>
          <input
            type="text"
            placeholder="Enter node endpoint (e.g., http://127.0.0.1:9944)"
            value={nodeEndpoint}
            onChange={(e) => setNodeEndpoint(e.target.value)}
            style={{ 
              flex: 1, 
              padding: '6px 8px', 
              border: '1px solid #ccc', 
              borderRadius: 4, 
              fontSize: '14px',
              fontFamily: 'monospace'
            }}
          />
          <button 
            onClick={testNodeConnection}
            disabled={isTestingConnection || !nodeEndpoint.trim()}
            style={{ 
              padding: '6px 12px', 
              backgroundColor: isTestingConnection || !nodeEndpoint.trim() ? '#f0f0f0' : '#007bff', 
              color: isTestingConnection || !nodeEndpoint.trim() ? '#666' : 'white',
              border: 'none', 
              borderRadius: 4, 
              cursor: isTestingConnection || !nodeEndpoint.trim() ? 'not-allowed' : 'pointer',
              fontSize: '14px',
              minWidth: '80px'
            }}
          >
            {isTestingConnection ? 'Testing...' : 'Test'}
          </button>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '14px' }}>
          <span><strong>Status:</strong></span>
          <span style={{ 
            color: nodeStatus === 'connected' ? '#28a745' : nodeStatus === 'error' ? '#dc3545' : '#6c757d',
            fontWeight: 'bold'
          }}>
            {nodeStatus === 'connected' ? '✅ Connected' : nodeStatus === 'error' ? '❌ Error' : '⚪ Unknown'}
          </span>
          {nodeStatus === 'connected' && (
            <span style={{ color: '#6c757d', fontSize: '12px' }}>
              ({nodeEndpoint})
            </span>
          )}
        </div>
      </div>

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

      <h2>Token Operations</h2>
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

      {/* Token Management Section */}
      <div style={{ marginBottom: 16, padding: 16, border: '1px solid #e1e5e9', borderRadius: 8, background: '#fafbfc' }}>
        <h3 style={{ margin: '0 0 16px 0', fontSize: '16px' }}>Token Portfolio</h3>
        
        {/* Add Token Input */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16 }}>
          <label style={{ minWidth: '120px', fontSize: '14px' }}>Add Token:</label>
          <input
            type="text"
            placeholder="Enter 64-character hex token address"
            value={newTokenAddress}
            onChange={(e) => setNewTokenAddress(e.target.value)}
            style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4, fontSize: '12px', fontFamily: 'monospace' }}
          />
          <button 
            onClick={addTokenAddress}
            disabled={!newTokenAddress.trim()}
            style={{ 
              padding: '6px 12px', 
              backgroundColor: !newTokenAddress.trim() ? '#f0f0f0' : '#28a745', 
              color: !newTokenAddress.trim() ? '#666' : 'white',
              border: 'none', 
              borderRadius: 4, 
              cursor: !newTokenAddress.trim() ? 'not-allowed' : 'pointer',
              fontSize: '14px'
            }}
          >
            Add
          </button>
          {coinAddress && (
            <button 
              onClick={() => setNewTokenAddress(coinAddress)} 
              style={{ padding: '6px 8px', fontSize: '12px', whiteSpace: 'nowrap' }}
            >
              Use My Coin
            </button>
          )}
        </div>

        {/* Query Balances Button */}
        {tokenAddresses.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <button 
              onClick={queryAllBalances}
              disabled={!currentWallet || isQueryingBalances}
              style={{ 
                padding: '8px 16px', 
                backgroundColor: !currentWallet || isQueryingBalances ? '#f0f0f0' : '#007bff', 
                color: !currentWallet || isQueryingBalances ? '#666' : 'white',
                border: 'none', 
                borderRadius: 4, 
                cursor: !currentWallet || isQueryingBalances ? 'not-allowed' : 'pointer',
                fontSize: '14px'
              }}
            >
              {isQueryingBalances ? 'Querying...' : `Query Balances (${tokenAddresses.length} tokens)`}
            </button>
          </div>
        )}

        {/* Token List */}
        {tokenAddresses.length > 0 && (
          <div>
            <h4 style={{ margin: '0 0 12px 0', fontSize: '14px' }}>Your Tokens:</h4>
            <div style={{ display: 'grid', gap: 8 }}>
              {tokenAddresses.map((tokenAddr) => {
                const tokenData = tokenBalances[tokenAddr]
                const displayBalance = tokenData?.balance ?? '0'
                const hasBalance = tokenData?.balance !== null
                
                return (
                  <div key={tokenAddr} style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: 8, 
                    padding: 8, 
                    border: '1px solid #ddd', 
                    borderRadius: 4, 
                    background: 'white',
                    fontSize: '12px'
                  }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontFamily: 'monospace', marginBottom: 2 }}>
                        <strong>Token:</strong> {tokenAddr}
                      </div>
                      <div style={{ 
                        color: hasBalance ? '#28a745' : '#6c757d',
                        fontWeight: hasBalance ? 'bold' : 'normal'
                      }}>
                        <strong>Balance:</strong> {displayBalance} {!hasBalance && '(no coinstore)'}
                      </div>
                      {tokenData?.coinStoreAddress && tokenData.coinStoreAddress !== 'unknown' && (
                        <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#666' }}>
                          <strong>CoinStore:</strong> {tokenData.coinStoreAddress}
                        </div>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: 4 }}>
                      {tokenData?.coinStoreAddress && tokenData.coinStoreAddress !== 'unknown' && (
                        <button 
                          onClick={() => {
                            setViewAddress(tokenData.coinStoreAddress)
                            setViewType('CoinStore')
                          }}
                          style={{ 
                            padding: '4px 6px', 
                            fontSize: '11px', 
                            backgroundColor: '#007bff',
                            color: 'white',
                            border: 'none',
                            borderRadius: 3,
                            cursor: 'pointer'
                          }}
                        >
                          View
                        </button>
                      )}
                      <button 
                        onClick={() => removeTokenAddress(tokenAddr)}
                        style={{ 
                          padding: '4px 6px', 
                          fontSize: '11px', 
                          backgroundColor: '#dc3545',
                          color: 'white',
                          border: 'none',
                          borderRadius: 3,
                          cursor: 'pointer'
                        }}
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {tokenAddresses.length === 0 && (
          <div style={{ textAlign: 'center', color: '#666', fontSize: '14px', padding: 16 }}>
            No tokens added yet. Add a token address above to track your balance.
          </div>
        )}
      </div>

      {/* Transfer Section */}
      <div style={{ marginBottom: 16, padding: 16, border: '1px solid #e1e5e9', borderRadius: 8, background: '#fafbfc' }}>
        <h3 style={{ margin: '0 0 16px 0', fontSize: '16px' }}>Transfer Tokens</h3>
        
        <div style={{ display: 'grid', gap: 8, marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Coin Address:</label>
            <input
              type="text"
              placeholder="Enter 64-character hex coin address"
              value={transferCoinAddress}
              onChange={(e) => setTransferCoinAddress(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4, fontSize: '12px', fontFamily: 'monospace' }}
            />
            {coinAddress && (
              <button 
                onClick={() => setTransferCoinAddress(coinAddress)} 
                style={{ padding: '4px 8px', fontSize: '12px', whiteSpace: 'nowrap' }}
              >
                Use My Coin
              </button>
            )}
          </div>
          
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Receiver Address:</label>
            <input
              type="text"
              placeholder="Enter 64-character hex address"
              value={transferReceiverAddress}
              onChange={(e) => setTransferReceiverAddress(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4, fontSize: '12px', fontFamily: 'monospace' }}
            />
            <button 
              onClick={populateReceiverWithMyAccount} 
              disabled={!currentWallet}
              style={{ padding: '4px 8px', fontSize: '12px', whiteSpace: 'nowrap' }}
            >
              Use My Account
            </button>
          </div>
          
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Amount:</label>
            <input
              type="number"
              placeholder="Amount to transfer"
              value={transferAmount}
              onChange={(e) => setTransferAmount(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4 }}
              min="1"
            />
          </div>
        </div>
        
        <button 
          onClick={onTransfer} 
          disabled={!currentWallet || !transferCoinAddress.trim() || !transferReceiverAddress.trim()}
          style={{ 
            padding: '8px 16px', 
            backgroundColor: !currentWallet || !transferCoinAddress.trim() || !transferReceiverAddress.trim() ? '#f0f0f0' : '#0066cc', 
            color: !currentWallet || !transferCoinAddress.trim() || !transferReceiverAddress.trim() ? '#666' : 'white',
            border: 'none', 
            borderRadius: 4, 
            cursor: !currentWallet || !transferCoinAddress.trim() || !transferReceiverAddress.trim() ? 'not-allowed' : 'pointer' 
          }}
        >
          Transfer Tokens
        </button>
        
        {!currentWallet && (
          <div style={{ marginTop: 8, fontSize: '12px', color: '#666' }}>
            Connect a wallet first
          </div>
        )}
      </div>

      {/* Display receiver's coinstore address after successful transfer */}
      {lastTransferReceiverCoinStore && (
        <div style={{ marginBottom: 16, padding: 12, border: '1px solid #d1f2eb', borderRadius: 8, background: '#d5f4e6' }}>
          <div style={{ marginBottom: 8 }}>
            <strong style={{ color: '#0f5132' }}>✅ Transfer Completed</strong>
          </div>
          <div style={{ marginBottom: 4, fontSize: '14px' }}>
            <strong>Receiver's CoinStore Address:</strong>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <code style={{ 
              display: 'block', 
              background: '#ffffff', 
              padding: 8, 
              borderRadius: 4, 
              fontSize: '12px', 
              wordBreak: 'break-all',
              flex: 1,
              border: '1px solid #c3e6cb'
            }}>
              {lastTransferReceiverCoinStore}
            </code>
            <button 
              onClick={() => {
                setViewAddress(lastTransferReceiverCoinStore)
                setViewType('CoinStore')
              }}
              style={{ 
                padding: '4px 8px', 
                fontSize: '12px', 
                backgroundColor: '#198754',
                color: 'white',
                border: 'none',
                borderRadius: 4,
                cursor: 'pointer',
                whiteSpace: 'nowrap'
              }}
            >
              View Balance
            </button>
          </div>
        </div>
      )}

      {coinAddress && (
        <div style={{ marginBottom: 16 }}>
          <div><strong>Coin Address:</strong></div>
          <code style={{ display: 'block', background: '#f6f8fa', padding: 8, borderRadius: 4, fontSize: '12px', wordBreak: 'break-all' }}>
            {coinAddress}
          </code>
        </div>
      )}

      <hr style={{ margin: '24px 0' }} />

      <h2>Orderbook Operations</h2>
      
      {/* Create Orderbook Section */}
      <div style={{ marginBottom: 16, padding: 16, border: '1px solid #e1e5e9', borderRadius: 8, background: '#fafbfc' }}>
        <h3 style={{ margin: '0 0 16px 0', fontSize: '16px' }}>Create Orderbook</h3>
        
        <div style={{ display: 'grid', gap: 8, marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Buy Asset:</label>
            <input
              type="text"
              placeholder="Enter 64-character hex coin address"
              value={orderbookBuyAsset}
              onChange={(e) => setOrderbookBuyAsset(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4, fontSize: '12px', fontFamily: 'monospace' }}
            />
            {coinAddress && (
              <button 
                onClick={() => setOrderbookBuyAsset(coinAddress)} 
                style={{ padding: '4px 8px', fontSize: '12px', whiteSpace: 'nowrap' }}
              >
                Use My Coin
              </button>
            )}
          </div>
          
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Sell Asset:</label>
            <input
              type="text"
              placeholder="Enter 64-character hex coin address"
              value={orderbookSellAsset}
              onChange={(e) => setOrderbookSellAsset(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4, fontSize: '12px', fontFamily: 'monospace' }}
            />
            {coinAddress && (
              <button 
                onClick={() => setOrderbookSellAsset(coinAddress)} 
                style={{ padding: '4px 8px', fontSize: '12px', whiteSpace: 'nowrap' }}
              >
                Use My Coin
              </button>
            )}
          </div>
        </div>
        
        <button 
          onClick={onCreateOrderbook} 
          disabled={!currentWallet || !orderbookBuyAsset.trim() || !orderbookSellAsset.trim()}
          style={{ 
            padding: '8px 16px', 
            backgroundColor: !currentWallet || !orderbookBuyAsset.trim() || !orderbookSellAsset.trim() ? '#f0f0f0' : '#0066cc', 
            color: !currentWallet || !orderbookBuyAsset.trim() || !orderbookSellAsset.trim() ? '#666' : 'white',
            border: 'none', 
            borderRadius: 4, 
            cursor: !currentWallet || !orderbookBuyAsset.trim() || !orderbookSellAsset.trim() ? 'not-allowed' : 'pointer' 
          }}
        >
          Create Orderbook
        </button>
      </div>

      {/* Display created orderbook address */}
      {createdOrderbookAddress && (
        <div style={{ marginBottom: 16, padding: 12, border: '1px solid #d1f2eb', borderRadius: 8, background: '#d5f4e6' }}>
          <div style={{ marginBottom: 8 }}>
            <strong style={{ color: '#0f5132' }}>✅ Orderbook Created</strong>
          </div>
          <div style={{ marginBottom: 4, fontSize: '14px' }}>
            <strong>Orderbook Address:</strong>
          </div>
          <code style={{ 
            display: 'block', 
            background: '#ffffff', 
            padding: 8, 
            borderRadius: 4, 
            fontSize: '12px', 
            wordBreak: 'break-all',
            border: '1px solid #c3e6cb'
          }}>
            {createdOrderbookAddress}
          </code>
        </div>
      )}

      {/* Place Limit Order Section */}
      <div style={{ marginBottom: 16, padding: 16, border: '1px solid #e1e5e9', borderRadius: 8, background: '#fafbfc' }}>
        <h3 style={{ margin: '0 0 16px 0', fontSize: '16px' }}>Place Limit Order</h3>
        
        <div style={{ display: 'grid', gap: 8, marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Orderbook:</label>
            <input
              type="text"
              placeholder="Enter 64-character hex orderbook address"
              value={limitOrderOrderbookAddress}
              onChange={(e) => setLimitOrderOrderbookAddress(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4, fontSize: '12px', fontFamily: 'monospace' }}
            />
            {createdOrderbookAddress && (
              <button 
                onClick={() => setLimitOrderOrderbookAddress(createdOrderbookAddress)} 
                style={{ padding: '4px 8px', fontSize: '12px', whiteSpace: 'nowrap' }}
              >
                Use My Orderbook
              </button>
            )}
          </div>
          
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Order Type:</label>
            <select
              value={limitOrderIsBuy ? 'buy' : 'sell'}
              onChange={(e) => setLimitOrderIsBuy(e.target.value === 'buy')}
              style={{ padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4 }}
            >
              <option value="buy">BUY</option>
              <option value="sell">SELL</option>
            </select>
          </div>
          
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Amount:</label>
            <input
              type="number"
              placeholder="Order amount"
              value={limitOrderAmount}
              onChange={(e) => setLimitOrderAmount(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4 }}
              min="1"
            />
          </div>
          
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ minWidth: '120px', fontSize: '14px' }}>Tick Price:</label>
            <input
              type="number"
              placeholder="Price tick"
              value={limitOrderTickPrice}
              onChange={(e) => setLimitOrderTickPrice(e.target.value)}
              style={{ flex: 1, padding: '6px 8px', border: '1px solid #ccc', borderRadius: 4 }}
              min="1"
            />
          </div>
        </div>
        
        <button 
          onClick={onPlaceLimitOrder} 
          disabled={!currentWallet || !limitOrderOrderbookAddress.trim() || !limitOrderAmount.trim() || !limitOrderTickPrice.trim()}
          style={{ 
            padding: '8px 16px', 
            backgroundColor: !currentWallet || !limitOrderOrderbookAddress.trim() || !limitOrderAmount.trim() || !limitOrderTickPrice.trim() ? '#f0f0f0' : (limitOrderIsBuy ? '#28a745' : '#dc3545'), 
            color: !currentWallet || !limitOrderOrderbookAddress.trim() || !limitOrderAmount.trim() || !limitOrderTickPrice.trim() ? '#666' : 'white',
            border: 'none', 
            borderRadius: 4, 
            cursor: !currentWallet || !limitOrderOrderbookAddress.trim() || !limitOrderAmount.trim() || !limitOrderTickPrice.trim() ? 'not-allowed' : 'pointer' 
          }}
        >
          Place {limitOrderIsBuy ? 'BUY' : 'SELL'} Order
        </button>
        
        {!currentWallet && (
          <div style={{ marginTop: 8, fontSize: '12px', color: '#666' }}>
            Connect a wallet first
          </div>
        )}
      </div>

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
          <option value="Orderbook">Orderbook</option>
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
        <button onClick={() => { setViewAddress(createdOrderbookAddress); setViewType('Orderbook') }} disabled={!createdOrderbookAddress} style={{ padding: '4px 8px' }}>
          My Orderbook
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

      <hr style={{ margin: '24px 0' }} />

      <OrderbookVisualizer initialOrderbookAddress={createdOrderbookAddress} makeRpcCall={makeRpcCall} />

      <hr style={{ margin: '24px 0' }} />

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
