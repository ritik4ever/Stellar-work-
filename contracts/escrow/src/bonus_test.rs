use super::*;

#[test]
fn test_early_completion_bonus_conserves_funded_amount() {
    let env = Env::default();
    let (_admin, client, freelancer, token, contract_id) = setup_test(&env);
    let escrow = new_escrow(&env, &contract_id);
    let desc_hash = BytesN::from_array(&env, &[1u8; 32]);
    let deadline: u64 = 1000;
    let amount: i128 = 100_0000000;
    let bonus: i128 = 50_0000000;
    let token_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
    let initial_client_balance = token_client.balance(&client);

    let job_id = escrow.post_job_with_categories(
        &client,
        &amount,
        &bonus,
        &desc_hash,
        &100u32,
        &deadline,
        &token,
        &vec![&env],
    );
    assert_eq!(escrow.get_job(&job_id).bonus_amount, bonus);
    assert_eq!(escrow.get_job_escrow_balance(&job_id), amount + bonus);

    escrow.accept_job(&freelancer, &job_id);
    escrow.submit_work(&freelancer, &job_id);
    env.ledger().with_mut(|l| l.timestamp = 500);
    escrow.approve_work(&client, &job_id);

    let job = escrow.get_job(&job_id);
    assert!(job.bonus_paid);
    assert_eq!(job.status, JobStatus::Completed);
    assert_eq!(
        token_client.balance(&client),
        initial_client_balance - amount - bonus / 2
    );
    assert_eq!(
        token_client.balance(&freelancer),
        amount - amount * 250 / 10_000 + bonus / 2
    );
    assert_eq!(token_client.balance(&contract_id), amount * 250 / 10_000);
    assert_eq!(escrow.get_job_escrow_balance(&job_id), 0);
}

#[test]
fn test_late_completion_refunds_bonus_and_conserves_funded_amount() {
    let env = Env::default();
    let (_admin, client, freelancer, token, contract_id) = setup_test(&env);
    let escrow = new_escrow(&env, &contract_id);
    let desc_hash = BytesN::from_array(&env, &[2u8; 32]);
    let deadline: u64 = 1000;
    let amount: i128 = 100_0000000;
    let bonus: i128 = 50_0000000;
    let token_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
    let initial_client_balance = token_client.balance(&client);

    let job_id = escrow.post_job_with_categories(
        &client,
        &amount,
        &bonus,
        &desc_hash,
        &100u32,
        &deadline,
        &token,
        &vec![&env],
    );
    escrow.accept_job(&freelancer, &job_id);
    escrow.submit_work(&freelancer, &job_id);
    env.ledger().with_mut(|l| l.timestamp = deadline + 1);
    escrow.approve_work(&client, &job_id);

    let job = escrow.get_job(&job_id);
    assert!(job.bonus_paid);
    assert_eq!(job.status, JobStatus::Completed);
    assert_eq!(
        token_client.balance(&client),
        initial_client_balance - amount
    );
    assert_eq!(
        token_client.balance(&freelancer),
        amount - amount * 250 / 10_000
    );
    assert_eq!(token_client.balance(&contract_id), amount * 250 / 10_000);
    assert_eq!(escrow.get_job_escrow_balance(&job_id), 0);
}

#[test]
fn test_cancel_with_bonus_refunds_full_escrow() {
    let env = Env::default();
    let (_admin, client, _freelancer, token, contract_id) = setup_test(&env);
    let escrow = new_escrow(&env, &contract_id);
    let desc_hash = BytesN::from_array(&env, &[3u8; 32]);
    let deadline: u64 = 1000;
    let amount: i128 = 100_0000000;
    let bonus: i128 = 50_0000000;
    let token_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
    let initial_client_balance = token_client.balance(&client);

    let job_id = escrow.post_job_with_categories(
        &client,
        &amount,
        &bonus,
        &desc_hash,
        &100u32,
        &deadline,
        &token,
        &vec![&env],
    );
    assert_eq!(escrow.get_job(&job_id).bonus_amount, bonus);
    assert_eq!(escrow.get_job_escrow_balance(&job_id), amount + bonus);
    assert_eq!(token_client.balance(&contract_id), amount + bonus);

    escrow.cancel_job(&client, &job_id);

    let job = escrow.get_job(&job_id);
    assert_eq!(job.status, JobStatus::Cancelled);
    assert!(job.bonus_paid);
    assert_eq!(token_client.balance(&client), initial_client_balance);
    assert_eq!(token_client.balance(&contract_id), 0);
    assert_eq!(escrow.get_job_escrow_balance(&job_id), 0);
}
