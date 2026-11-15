import pytest

from verifiers import tinfoil_amd

# Lowest TCB across the retained Tinfoil captures (router.inf6 v3). Both fall
# below the AMD-published Genoa minimum, so tests that need verify_bundle to
# get past the TCB check substitute this table; test_tinfoil_amd_chain covers the pinned one.
RETAINED_TCB = {"bl": 10, "tee": 0, "snp": 0x17, "ucode_by_stepping": {"1": 0x54}}


@pytest.fixture
def retained_tcb_minimum(monkeypatch):
    monkeypatch.setattr(tinfoil_amd, "TCB_MINIMUM", RETAINED_TCB)
