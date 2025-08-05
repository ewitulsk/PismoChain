import { SuiClient, getFullnodeUrl } from '@mysten/sui.js/client';
import { TransactionBlock } from '@mysten/sui.js/transactions';
import { Ed25519Keypair } from '@mysten/sui.js/keypairs/ed25519';
import { fromHEX } from '@mysten/sui.js/utils';
import { CONFIG } from './config';
import { LockerBox, LockResult, UnlockResult, TransactionOptions } from './types';

export class PismoLockerClient {
  private client: SuiClient;
  private keypair: Ed25519Keypair | null = null;

  constructor(privateKey?: string) {
    this.client = new SuiClient({ url: getFullnodeUrl(CONFIG.NETWORK as any) });
    
    if (privateKey) {
      this.keypair = Ed25519Keypair.fromSecretKey(fromHEX(privateKey));
    }
  }

  /**
   * Set the keypair for signing transactions
   */
  setKeypair(privateKey: string): void {
    this.keypair = Ed25519Keypair.fromSecretKey(fromHEX(privateKey));
  }

  /**
   * Get the current signer address
   */
  getAddress(): string {
    if (!this.keypair) {
      throw new Error('Keypair not set. Call setKeypair() first.');
    }
    return this.keypair.toSuiAddress();
  }

  /**
   * Lock coins into a new LockerBox
   * @param coinId - The ID of the coin to lock
   * @param coinType - The type of the coin (e.g., '0x2::sui::SUI')
   * @param options - Transaction options
   */
  async lockNew<T extends string>(
    coinId: string,
    coinType: T,
    options: TransactionOptions = {}
  ): Promise<LockResult> {
    if (!this.keypair) {
      throw new Error('Keypair not set. Call setKeypair() first.');
    }

    const txb = new TransactionBlock();
    
    // Set gas budget
    txb.setGasBudget(options.gasBudget || CONFIG.GAS_BUDGET);

    // Call the lock_new function
    txb.moveCall({
      target: `${CONFIG.PISMO_LOCKER_PACKAGE_ID}::${CONFIG.MODULE_NAME}::${CONFIG.FUNCTIONS.LOCK_NEW}`,
      typeArguments: [coinType],
      arguments: [
        txb.object(coinId)
      ]
    });

    // Execute the transaction
    const result = await this.client.signAndExecuteTransactionBlock({
      signer: this.keypair,
      transactionBlock: txb,
      options: {
        showEvents: true,
        showEffects: true,
      }
    });

    return {
      transactionResult: result,
      events: result.events || []
    };
  }

  /**
   * Lock coins into an existing LockerBox
   * @param coinId - The ID of the coin to lock
   * @param lockerBoxId - The ID of the existing LockerBox
   * @param coinType - The type of the coin
   * @param options - Transaction options
   */
  async lockExisting<T extends string>(
    coinId: string,
    lockerBoxId: string,
    coinType: T,
    options: TransactionOptions = {}
  ): Promise<LockResult> {
    if (!this.keypair) {
      throw new Error('Keypair not set. Call setKeypair() first.');
    }

    const txb = new TransactionBlock();
    
    // Set gas budget
    txb.setGasBudget(options.gasBudget || CONFIG.GAS_BUDGET);

    // Call the lock_existing function
    txb.moveCall({
      target: `${CONFIG.PISMO_LOCKER_PACKAGE_ID}::${CONFIG.MODULE_NAME}::${CONFIG.FUNCTIONS.LOCK_EXISTING}`,
      typeArguments: [coinType],
      arguments: [
        txb.object(coinId),
        txb.object(lockerBoxId)
      ]
    });

    // Execute the transaction
    const result = await this.client.signAndExecuteTransactionBlock({
      signer: this.keypair,
      transactionBlock: txb,
      options: {
        showEvents: true,
        showEffects: true,
      }
    });

    return {
      transactionResult: result,
      events: result.events || []
    };
  }

  /**
   * Unlock coins from a LockerBox
   * @param lockerBoxId - The ID of the LockerBox
   * @param amount - The amount to unlock
   * @param coinType - The type of the coin
   * @param options - Transaction options
   */
  async unlock<T extends string>(
    lockerBoxId: string,
    amount: string | number,
    coinType: T,
    options: TransactionOptions = {}
  ): Promise<UnlockResult> {
    if (!this.keypair) {
      throw new Error('Keypair not set. Call setKeypair() first.');
    }

    const txb = new TransactionBlock();
    
    // Set gas budget
    txb.setGasBudget(options.gasBudget || CONFIG.GAS_BUDGET);

    // Call the unlock function
    const [coin] = txb.moveCall({
      target: `${CONFIG.PISMO_LOCKER_PACKAGE_ID}::${CONFIG.MODULE_NAME}::${CONFIG.FUNCTIONS.UNLOCK}`,
      typeArguments: [coinType],
      arguments: [
        txb.object(lockerBoxId),
        txb.pure(amount.toString())
      ]
    });

    // Transfer the unlocked coin to the sender
    txb.transferObjects([coin], txb.gas);

    // Execute the transaction
    const result = await this.client.signAndExecuteTransactionBlock({
      signer: this.keypair,
      transactionBlock: txb,
      options: {
        showEvents: true,
        showEffects: true,
      }
    });

    // Extract the coin ID from the created objects
    const coinId = result.effects?.created?.[0]?.reference?.objectId || '';

    return {
      transactionResult: result,
      coinId,
      events: result.events || []
    };
  }

  /**
   * Get the balance of a LockerBox
   * @param lockerBoxId - The ID of the LockerBox
   * @param coinType - The type of the coin
   */
  async getBalance<T extends string>(lockerBoxId: string, coinType: T): Promise<string> {
    const txb = new TransactionBlock();

    const [balance] = txb.moveCall({
      target: `${CONFIG.PISMO_LOCKER_PACKAGE_ID}::${CONFIG.MODULE_NAME}::${CONFIG.FUNCTIONS.BALANCE}`,
      typeArguments: [coinType],
      arguments: [txb.object(lockerBoxId)]
    });

    const result = await this.client.devInspectTransactionBlock({
      transactionBlock: txb,
      sender: this.keypair?.toSuiAddress() || '0x0'
    });

    if (result.results?.[0]?.returnValues?.[0]) {
      const [balanceBytes] = result.results[0].returnValues[0];
      return balanceBytes.toString();
    }

    throw new Error('Failed to get balance');
  }

  /**
   * Get the owner of a LockerBox
   * @param lockerBoxId - The ID of the LockerBox
   * @param coinType - The type of the coin
   */
  async getOwner<T extends string>(lockerBoxId: string, coinType: T): Promise<string> {
    const txb = new TransactionBlock();

    const [owner] = txb.moveCall({
      target: `${CONFIG.PISMO_LOCKER_PACKAGE_ID}::${CONFIG.MODULE_NAME}::${CONFIG.FUNCTIONS.OWNER}`,
      typeArguments: [coinType],
      arguments: [txb.object(lockerBoxId)]
    });

    const result = await this.client.devInspectTransactionBlock({
      transactionBlock: txb,
      sender: this.keypair?.toSuiAddress() || '0x0'
    });

    if (result.results?.[0]?.returnValues?.[0]) {
      const [ownerBytes] = result.results[0].returnValues[0];
      return `0x${Buffer.from(ownerBytes).toString('hex')}`;
    }

    throw new Error('Failed to get owner');
  }

  /**
   * Get LockerBox objects owned by an address
   * @param owner - The owner address
   * @param coinType - The type of the coin
   */
  async getLockerBoxes<T extends string>(owner: string, coinType: T): Promise<LockerBox[]> {
    const objects = await this.client.getOwnedObjects({
      owner,
      filter: {
        StructType: `${CONFIG.PISMO_LOCKER_PACKAGE_ID}::${CONFIG.MODULE_NAME}::LockerBox<${coinType}>`
      },
      options: {
        showContent: true
      }
    });

    return objects.data
      .filter(obj => obj.data?.content && 'fields' in obj.data.content)
      .map(obj => {
        const content = obj.data!.content as any;
        return {
          id: obj.data!.objectId,
          balance: content.fields.balance.toString(),
          owner: content.fields.owner,
          coinType
        };
      });
  }

  /**
   * Get all coins of a specific type owned by an address
   * @param owner - The owner address  
   * @param coinType - The type of the coin
   */
  async getCoins<T extends string>(owner: string, coinType: T) {
    return await this.client.getCoins({
      owner,
      coinType
    });
  }
} 