from dataclasses import dataclass

@dataclass(frozen=True)
class CPAResult:
    wins: int
    trials: int
    @property
    def rate(self) -> float:
        return self.wins / self.trials if self.trials else 0.0

# Day 2 (ECB/GCM) & Day 3 (CTR fixed nonce) will implement these:
def run_trial_ecb() -> int:
    """Return 1 if attacker wins the IND-CPA trial for AES-ECB, else 0."""
    raise NotImplementedError("Week-2 Day 2: implement ECB CPA trial")

def run_trial_gcm() -> int:
    """Return 1 if attacker wins the IND-CPA trial for AES-GCM, else 0."""
    raise NotImplementedError("Week-2 Day 2: implement GCM CPA trial")

def run_trial_ctr_fixed_nonce() -> int:
    """Return 1 if attacker wins the IND-CPA trial for AES-CTR with fixed nonce, else 0."""
    raise NotImplementedError("Week-2 Day 3: implement CTR fixed-nonce CPA trial")
