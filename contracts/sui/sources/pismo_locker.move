/// Module: pismo_locker
module pismo_locker::pismo_locker {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::event;
    use sui::object::{UID};
    use sui::transfer;
    use sui::tx_context::{TxContext};
    use std::option::{Option};
    use std::type_name;

    // Error codes
    const EInsufficientBalance: u64 = 1;
    const ENotOwner: u64 = 2;
    const EZeroAmount: u64 = 3;

    /// Shared object that holds locked coins of a specific type
    public struct LockerBox<phantom T> has key, store {
        id: UID,
        balance: Balance<T>,
        owner: address,
    }

    /// Event emitted when coins are locked
    public struct LockEvent<phantom T> has copy, drop {
        locker_id: object::ID,
        owner: address,
        amount: u64,
        coin_type: std::type_name::TypeName,
    }

    /// Event emitted when coins are unlocked
    public struct UnlockEvent<phantom T> has copy, drop {
        locker_id: object::ID,
        owner: address,
        amount: u64,
        remaining_balance: u64,
        coin_type: std::type_name::TypeName,
    }

    /// Lock coins into a LockerBox. If this is the first time for this coin type,
    /// a new shared LockerBox will be created.
    public fun lock<T>(
        coin: Coin<T>,
        mut existing_locker: Option<LockerBox<T>>,
        ctx: &mut TxContext
    ): LockerBox<T> {
        let sender = tx_context::sender(ctx);
        let amount = coin::value(&coin);
        
        assert!(amount > 0, EZeroAmount);

        let locker = if (option::is_some(&existing_locker)) {
            let mut locker = option::extract(&mut existing_locker);
            
            // Verify ownership
            assert!(locker.owner == sender, ENotOwner);
            
            // Add the new coins to existing balance
            balance::join(&mut locker.balance, coin::into_balance(coin));
            locker
        } else {
            // Create new LockerBox
            let locker = LockerBox<T> {
                id: object::new(ctx),
                balance: coin::into_balance(coin),
                owner: sender,
            };
            locker
        };

        // Emit lock event
        event::emit(LockEvent<T> {
            locker_id: object::uid_to_inner(&locker.id),
            owner: sender,
            amount,
            coin_type: std::type_name::get<T>(),
        });

        // Clean up the option
        option::destroy_none(existing_locker);
        
        locker
    }

    /// Convenience function to lock coins when creating a new LockerBox
    public fun lock_new<T>(
        coin: Coin<T>,
        ctx: &mut TxContext
    ) {
        let locker = lock(coin, option::none<LockerBox<T>>(), ctx);
        transfer::share_object(locker);
    }

    /// Convenience function to lock coins into an existing LockerBox
    public fun lock_existing<T>(
        coin: Coin<T>,
        locker: LockerBox<T>,
        ctx: &mut TxContext
    ) {
        let updated_locker = lock(coin, option::some(locker), ctx);
        transfer::share_object(updated_locker);
    }

    /// Unlock specified amount of coins from a LockerBox
    public fun unlock<T>(
        locker: &mut LockerBox<T>,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<T> {
        let sender = tx_context::sender(ctx);
        
        // Verify ownership
        assert!(locker.owner == sender, ENotOwner);
        
        // Check sufficient balance
        assert!(balance::value(&locker.balance) >= amount, EInsufficientBalance);
        assert!(amount > 0, EZeroAmount);

        // Split the requested amount from the balance
        let unlocked_balance = balance::split(&mut locker.balance, amount);
        let remaining_balance = balance::value(&locker.balance);

        // Emit unlock event
        event::emit(UnlockEvent<T> {
            locker_id: object::uid_to_inner(&locker.id),
            owner: sender,
            amount,
            remaining_balance,
            coin_type: std::type_name::get<T>(),
        });

        // Convert balance back to coin
        coin::from_balance(unlocked_balance, ctx)
    }

    // === View Functions ===

    /// Get the balance amount in a LockerBox
    public fun balance<T>(locker: &LockerBox<T>): u64 {
        balance::value(&locker.balance)
    }

    /// Get the owner of a LockerBox
    public fun owner<T>(locker: &LockerBox<T>): address {
        locker.owner
    }

    /// Get the ID of a LockerBox
    public fun id<T>(locker: &LockerBox<T>): object::ID {
        object::uid_to_inner(&locker.id)
    }

    // === Test Functions ===
    
    #[test_only]
    use sui::test_scenario;
    #[test_only]
    use sui::sui::SUI;

    #[test]
    fun test_lock_new() {
        let mut scenario = test_scenario::begin(@0x1);
        let ctx = test_scenario::ctx(&mut scenario);
        
        // Create a test coin
        let coin = coin::mint_for_testing<SUI>(1000, ctx);
        
        // Lock the coin in a new LockerBox
        lock_new(coin, ctx);
        
        test_scenario::end(scenario);
    }

    #[test]
    fun test_lock_and_unlock() {
        let mut scenario = test_scenario::begin(@0x1);
        
        // Lock coins
        {
            let ctx = test_scenario::ctx(&mut scenario);
            let coin = coin::mint_for_testing<SUI>(1000, ctx);
            lock_new(coin, ctx);
        };
        
        // Unlock some coins
        test_scenario::next_tx(&mut scenario, @0x1);
        {
            let mut locker = test_scenario::take_shared<LockerBox<SUI>>(&mut scenario);
            let ctx = test_scenario::ctx(&mut scenario);
            
            assert!(balance(&locker) == 1000, 0);
            
            let unlocked_coin = unlock(&mut locker, 300, ctx);
            assert!(coin::value(&unlocked_coin) == 300, 1);
            assert!(balance(&locker) == 700, 2);
            
            coin::burn_for_testing(unlocked_coin);
            test_scenario::return_shared(locker);
        };
        
        test_scenario::end(scenario);
    }
}


