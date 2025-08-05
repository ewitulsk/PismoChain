# Pismo Locker TypeScript Client

A TypeScript client for interacting with the Pismo Locker smart contract deployed on Sui testnet.

## Overview

The Pismo Locker contract allows users to lock coins into secure containers (LockerBoxes) and unlock them later. This TypeScript client provides a convenient interface to interact with the contract functions.

## Contract Information

- **Package ID**: `0xecbd9e6965d58b933f3dddbc9c45621ad8aa0f4daf11c431a0bbc42aabad850b`
- **Network**: Sui Testnet
- **Module**: `pismo_locker`

## Installation

1. Navigate to the TypeScript project directory:
   ```bash
   cd contracts/sui/typescript
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Copy the environment configuration:
   ```bash
   cp .env.example .env
   ```

4. Edit `.env` and add your private key:
   ```
   PRIVATE_KEY=your-private-key-here
   ```

## Build

```bash
npm run build
```

## Usage

### Basic Client Setup

```typescript
import { PismoLockerClient } from './src/pismoLockerClient';

// Initialize client
const client = new PismoLockerClient();

// Set your private key
client.setKeypair('your-private-key-here');

// Get your address
const address = client.getAddress();
console.log('Your address:', address);
```

### Locking Coins

#### Lock coins in a new LockerBox

```typescript
// Get available coins
const coins = await client.getCoins(address, '0x2::sui::SUI');
const coinId = coins.data[0].coinObjectId;

// Lock the coin in a new LockerBox
const lockResult = await client.lockNew(coinId, '0x2::sui::SUI');
console.log('Transaction:', lockResult.transactionResult.digest);
```

#### Lock coins in an existing LockerBox

```typescript
// Get your existing LockerBoxes
const lockerBoxes = await client.getLockerBoxes(address, '0x2::sui::SUI');
const lockerBoxId = lockerBoxes[0].id;

// Lock additional coins
const lockResult = await client.lockExisting(coinId, lockerBoxId, '0x2::sui::SUI');
```

### Unlocking Coins

```typescript
// Get LockerBox balance
const balance = await client.getBalance(lockerBoxId, '0x2::sui::SUI');
console.log('Balance:', balance);

// Unlock some coins
const unlockResult = await client.unlock(lockerBoxId, 1000, '0x2::sui::SUI');
console.log('Unlocked coin ID:', unlockResult.coinId);
```

### Querying Information

```typescript
// Get all your LockerBoxes
const lockerBoxes = await client.getLockerBoxes(address, '0x2::sui::SUI');

// Get balance of a specific LockerBox
const balance = await client.getBalance(lockerBoxId, '0x2::sui::SUI');

// Get owner of a LockerBox
const owner = await client.getOwner(lockerBoxId, '0x2::sui::SUI');

// Get your available coins
const coins = await client.getCoins(address, '0x2::sui::SUI');
```

## API Reference

### PismoLockerClient

#### Constructor
- `new PismoLockerClient(privateKey?: string)`

#### Methods

##### Authentication
- `setKeypair(privateKey: string): void` - Set the signing keypair
- `getAddress(): string` - Get the current signer address

##### Lock Functions
- `lockNew<T>(coinId: string, coinType: T, options?: TransactionOptions): Promise<LockResult>` - Lock coins in a new LockerBox
- `lockExisting<T>(coinId: string, lockerBoxId: string, coinType: T, options?: TransactionOptions): Promise<LockResult>` - Lock coins in an existing LockerBox

##### Unlock Functions
- `unlock<T>(lockerBoxId: string, amount: string | number, coinType: T, options?: TransactionOptions): Promise<UnlockResult>` - Unlock coins from a LockerBox

##### Query Functions
- `getBalance<T>(lockerBoxId: string, coinType: T): Promise<string>` - Get LockerBox balance
- `getOwner<T>(lockerBoxId: string, coinType: T): Promise<string>` - Get LockerBox owner
- `getLockerBoxes<T>(owner: string, coinType: T): Promise<LockerBox[]>` - Get all LockerBoxes owned by an address
- `getCoins<T>(owner: string, coinType: T)` - Get all coins of a specific type owned by an address

## Scripts

- `npm run build` - Compile TypeScript to JavaScript
- `npm run dev` - Run the example with ts-node
- `npm start` - Run the compiled JavaScript
- `npm run lint` - Lint the code
- `npm run format` - Format the code with Prettier

## Configuration

The client can be configured through environment variables:

- `SUI_RPC_URL` - Sui RPC endpoint (default: testnet)
- `SUI_NETWORK` - Network name (default: 'testnet')
- `PISMO_LOCKER_PACKAGE_ID` - Contract package ID
- `PRIVATE_KEY` - Your private key for signing transactions
- `GAS_BUDGET` - Gas budget for transactions (default: 10000000)

## Error Handling

The client includes proper error handling for common scenarios:

- Missing private key
- Insufficient balance
- Invalid coin IDs
- Network errors

Always wrap your calls in try-catch blocks:

```typescript
try {
  const result = await client.lockNew(coinId, '0x2::sui::SUI');
  console.log('Success:', result);
} catch (error) {
  console.error('Failed:', error.message);
}
```

## Example

Run the included example:

```bash
npm run dev
```

This will demonstrate basic usage of the client with your configured private key.

## License

MIT 