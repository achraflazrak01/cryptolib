from cryptolib.experiments.cpa import run_trial_ecb, run_trial_gcm, run_trial_ctr_fixed_nonce, CPAResult

def _estimate(trials: int, fn) -> CPAResult:
    wins = 0
    for _ in range(trials):
        wins += fn()
    return CPAResult(wins=wins, trials=trials)

def test_ecb_beats_ind_cpa_attacker():
    r = _estimate(200, run_trial_ecb)
    # ECB leaks identical blocks -> attacker should win clearly > 0.9
    assert r.rate > 0.90

def test_gcm_looks_random_to_same_attacker():
    r = _estimate(200, run_trial_gcm)
    # randomized AEAD -> attacker should be ~random
    assert 0.40 <= r.rate <= 0.60

def test_ctr_fixed_nonce_is_deterministic_breaks_ind_cpa():
    r = _estimate(100, run_trial_ctr_fixed_nonce)
    # Deterministic encryption with oracle queries -> attacker wins ~1.0
    assert r.rate > 0.95