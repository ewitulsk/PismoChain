import dotenv from 'dotenv';

dotenv.config();

export const CONFIG = {
  // Sui Network Configuration
  RPC_URL: process.env.SUI_RPC_URL || 'https://fullnode.testnet.sui.io:443',
  NETWORK: process.env.SUI_NETWORK || 'testnet',
  
  // Contract Configuration
  PISMO_LOCKER_PACKAGE_ID: process.env.PISMO_LOCKER_PACKAGE_ID || '0xecbd9e6965d58b933f3dddbc9c45621ad8aa0f4daf11c431a0bbc42aabad850b',
  
  // Wallet Configuration
  PRIVATE_KEY: process.env.PRIVATE_KEY || '',
  
  // Gas Configuration
  GAS_BUDGET: parseInt(process.env.GAS_BUDGET || '10000000'),
  
  // Module and Function Names
  MODULE_NAME: 'pismo_locker',
  FUNCTIONS: {
    LOCK_NEW: 'lock_new',
    LOCK_EXISTING: 'lock_existing', 
    UNLOCK: 'unlock',
    BALANCE: 'balance',
    OWNER: 'owner',
    ID: 'id',
  }
} as const; 