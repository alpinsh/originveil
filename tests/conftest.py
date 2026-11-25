import pytest

# The repo root is also a package (the Hermes plugin). Import the CLI package first so
# "originveil" always means the inner package, whatever order tests run in.
import originveil.net  # noqa: F401

from helpers import CF


@pytest.fixture
def cf_nets():
    return list(CF)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests never touch the network or real resolvers."""
    from originveil import net

    monkeypatch.setattr(net, "_cf_cache", list(CF))
    monkeypatch.setattr(net, "resolve", lambda host: set())
    monkeypatch.setattr(net, "dig", lambda name, rtype, timeout=5.0: [])
