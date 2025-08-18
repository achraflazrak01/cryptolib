from cryptolib.experiments.cca import run_trial_cca_ctr_fixed_nonce, run_trial_cca_gcm

def _estimate(trials, fn):
    wins = 0
    for _ in range(trials):
        wins += fn()
    return wins / trials

def test_cca_fixed_nonce_attack_succeeds():
    rate = _estimate(80, run_trial_cca_ctr_fixed_nonce)
    assert rate > 0.95

def test_cca_gcm_resists_attacks_success():
    rate = _estimate(200, run_trial_cca_gcm)
    assert 0.40 <= rate <= 0.60
