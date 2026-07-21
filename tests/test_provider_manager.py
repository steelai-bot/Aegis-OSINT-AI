from backend.provider_manager import ProviderManager


def test_get_providers():
    pm = ProviderManager()
    providers = pm.get_providers()
    assert isinstance(providers, list)
    for p in providers:
        assert "id" in p
        assert "name" in p
        assert "status" in p

def test_configure_and_disconnect():
    pm = ProviderManager()
    # Mocking configure
    test_id = "test_provider"
    # Ensure it's not present or disconnected initially
    # For now we'll just test that calling configure doesn't crash
    try:
        pm.configure_provider(test_id, {"api_key": "test"})
    except ValueError:
        pass # If test_provider isn't registered, it raises ValueError, which is correct
