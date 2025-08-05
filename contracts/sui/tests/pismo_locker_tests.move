#[test_only]
module pismo_locker::pismo_locker_tests {
    use pismo_locker::pismo_locker::{Self, LockerBox};
    use sui::test_scenario;
    use sui::coin;
    use sui::sui::SUI;

    #[test]
    fun test_complete_lock_unlock_flow() {
        let mut scenario = test_scenario::begin(@0x1);
        
        // Test locking coins in a new LockerBox
        {
            let ctx = test_scenario::ctx(&mut scenario);
            let coin = coin::mint_for_testing<SUI>(1000, ctx);
            pismo_locker::lock_new(coin, ctx);
        };
        
        // Test unlocking partial amount
        test_scenario::next_tx(&mut scenario, @0x1);
        {
            let mut locker = test_scenario::take_shared<LockerBox<SUI>>(&mut scenario);
            let ctx = test_scenario::ctx(&mut scenario);
            
            // Verify initial balance
            assert!(pismo_locker::balance(&locker) == 1000, 0);
            assert!(pismo_locker::owner(&locker) == @0x1, 1);
            
            // Unlock 300 coins
            let unlocked_coin = pismo_locker::unlock(&mut locker, 300, ctx);
            assert!(coin::value(&unlocked_coin) == 300, 2);
            assert!(pismo_locker::balance(&locker) == 700, 3);
            
            coin::burn_for_testing(unlocked_coin);
            test_scenario::return_shared(locker);
        };
        
        // Test adding more coins to existing LockerBox
        test_scenario::next_tx(&mut scenario, @0x1);
        {
            let locker = test_scenario::take_shared<LockerBox<SUI>>(&mut scenario);
            let ctx = test_scenario::ctx(&mut scenario);
            let additional_coin = coin::mint_for_testing<SUI>(500, ctx);
            
            pismo_locker::lock_existing(additional_coin, locker, ctx);
        };
        
        // Verify the balance increased
        test_scenario::next_tx(&mut scenario, @0x1);
        {
            let locker = test_scenario::take_shared<LockerBox<SUI>>(&mut scenario);
            
            assert!(pismo_locker::balance(&locker) == 1200, 4); // 700 + 500
            
            test_scenario::return_shared(locker);
        };
        
        test_scenario::end(scenario);
    }

    #[test, expected_failure(abort_code = 2)]
    fun test_unlock_wrong_owner() {
        let mut scenario = test_scenario::begin(@0x1);
        
        // User 1 creates a LockerBox
        {
            let ctx = test_scenario::ctx(&mut scenario);
            let coin = coin::mint_for_testing<SUI>(1000, ctx);
            pismo_locker::lock_new(coin, ctx);
        };
        
        // User 2 tries to unlock from User 1's LockerBox - should fail
        test_scenario::next_tx(&mut scenario, @0x2);
        {
            let mut locker = test_scenario::take_shared<LockerBox<SUI>>(&mut scenario);
            let ctx = test_scenario::ctx(&mut scenario);
            
            let unlocked_coin = pismo_locker::unlock(&mut locker, 100, ctx);
            coin::burn_for_testing(unlocked_coin);
            test_scenario::return_shared(locker);
        };
        
        test_scenario::end(scenario);
    }

    #[test, expected_failure(abort_code = 1)]
    fun test_unlock_insufficient_balance() {
        let mut scenario = test_scenario::begin(@0x1);
        
        // Create LockerBox with 100 coins
        {
            let ctx = test_scenario::ctx(&mut scenario);
            let coin = coin::mint_for_testing<SUI>(100, ctx);
            pismo_locker::lock_new(coin, ctx);
        };
        
        // Try to unlock 200 coins - should fail
        test_scenario::next_tx(&mut scenario, @0x1);
        {
            let mut locker = test_scenario::take_shared<LockerBox<SUI>>(&mut scenario);
            let ctx = test_scenario::ctx(&mut scenario);
            
            let unlocked_coin = pismo_locker::unlock(&mut locker, 200, ctx);
            coin::burn_for_testing(unlocked_coin);
            test_scenario::return_shared(locker);
        };
        
        test_scenario::end(scenario);
    }
}
