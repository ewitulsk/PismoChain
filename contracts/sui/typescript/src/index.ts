export { PismoLockerClient } from './pismoLockerClient';
export { CONFIG } from './config';
export * from './types';

import { PismoLockerClient } from './pismoLockerClient';
import { CONFIG } from './config';

/**
 * Example usage of the Pismo Locker Client
 */
async function example() {
  // Initialize client with private key
  const client = new PismoLockerClient();
  
  // Set private key (you would get this from environment or user input)
  if (CONFIG.PRIVATE_KEY) {
    client.setKeypair(CONFIG.PRIVATE_KEY);
    
    console.log('Client address:', client.getAddress());
    
    // Example: Get SUI coins owned by the address
    const coins = await client.getCoins(client.getAddress(), '0x2::sui::SUI');
    console.log('Available SUI coins:', coins.data.length);
    
    if (coins.data.length > 0) {
      const coinId = coins.data[0].coinObjectId;
      console.log('Using coin:', coinId);
      
      // Example: Lock coins in a new LockerBox
      try {
        const lockResult = await client.lockNew(coinId, '0x2::sui::SUI');
        console.log('Lock transaction successful:', lockResult.transactionResult.digest);
        console.log('Events:', lockResult.events);
      } catch (error) {
        console.error('Lock failed:', error);
      }
      
      // Example: Get LockerBoxes owned by the address
      const lockerBoxes = await client.getLockerBoxes(client.getAddress(), '0x2::sui::SUI');
      console.log('Owned LockerBoxes:', lockerBoxes);
      
      // Example: Unlock coins (if you have a LockerBox)
      if (lockerBoxes.length > 0) {
        const lockerBoxId = lockerBoxes[0].id;
        const balance = await client.getBalance(lockerBoxId, '0x2::sui::SUI');
        console.log('LockerBox balance:', balance);
        
        // Unlock half of the balance
        const unlockAmount = Math.floor(parseInt(balance) / 2);
        if (unlockAmount > 0) {
          try {
            const unlockResult = await client.unlock(lockerBoxId, unlockAmount, '0x2::sui::SUI');
            console.log('Unlock transaction successful:', unlockResult.transactionResult.digest);
            console.log('Unlocked coin ID:', unlockResult.coinId);
          } catch (error) {
            console.error('Unlock failed:', error);
          }
        }
      }
    }
  } else {
    console.log('No private key configured. Set PRIVATE_KEY environment variable to run examples.');
  }
}

// Run example if this file is executed directly
if (require.main === module) {
  example().catch(console.error);
} 