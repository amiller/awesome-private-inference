"""The tinfoil model->repo anchor check, on fixed inputs."""
from unittest.mock import patch

from verifiers import tinfoil


class _Resp:
    def __init__(self, text="", payload=None):
        self.text = text
        self._payload = payload

    def json(self):
        return self._payload


CONFIG = """
models:
  llama3-3-70b:
    repo: tinfoilsh/confidential-llama3-3-70b
  glm-5-2:
    repo: tinfoilsh/confidential-glm5-2-b200
"""


def _fake_get(pinned_config, served_ids):
    def get(url, timeout=30):
        if url == tinfoil.ROUTER_CONFIG_URL:
            return _Resp(text=pinned_config)
        return _Resp(payload={"data": [{"id": i} for i in served_ids]})
    return get


def test_every_served_model_pinned_is_clean():
    with patch.object(tinfoil.requests, "get", _fake_get(CONFIG, ["llama3-3-70b", "glm-5-2"])):
        anchor = tinfoil.model_repo_anchor()
    assert anchor["models_unpinned"] == []
    assert anchor["models_served"] == 2
    assert anchor["repos"] == ["tinfoilsh/confidential-glm5-2-b200",
                               "tinfoilsh/confidential-llama3-3-70b"]


def test_a_model_served_without_a_repo_pin_is_reported():
    # The regression this check exists for: the router serving something no
    # reviewed repo covers, now that we can no longer probe the enclave itself.
    with patch.object(tinfoil.requests, "get", _fake_get(CONFIG, ["llama3-3-70b", "mystery-7b"])):
        anchor = tinfoil.model_repo_anchor()
    assert anchor["models_unpinned"] == ["mystery-7b"]
