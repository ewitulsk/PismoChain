import { SuiTransactionBlockResponse } from '@mysten/sui.js/client';

export interface LockerBox {
  id: string;
  balance: string;
  owner: string;
  coinType: string;
}

export interface LockEvent {
  lockerId: string;
  owner: string;
  amount: string;
  coinType: string;
}

export interface UnlockEvent {
  lockerId: string;
  owner: string;
  amount: string;
  remainingBalance: string;
  coinType: string;
}

export interface TransactionOptions {
  gasBudget?: number;
}

export interface LockResult {
  transactionResult: SuiTransactionBlockResponse;
  lockerId?: string;
  events: any[];
}

export interface UnlockResult {
  transactionResult: SuiTransactionBlockResponse;
  coinId: string;
  events: any[];
} 