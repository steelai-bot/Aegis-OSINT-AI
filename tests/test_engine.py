from backend.engine import InvestigationEngine
from backend.models import PluginResponse


def test_extract_entities():
    engine = InvestigationEngine("data/test_engine.db")
    from backend.models import TargetType
    resp = PluginResponse(
        provider="test",
        entity_type=TargetType.DOMAIN,
        raw={"emails": ["test@example.com"], "domains": ["example.com"]},
        confidence=0.9
    )
    entities = engine.extract_entities(resp, target_id=1)

    assert len(entities) == 2
    types = [e.type.value for e in entities]
    assert "email" in types
    assert "domain" in types

def test_build_relationships():
    engine = InvestigationEngine("data/test_engine.db")
    from backend.models import Entity, EntityType

    domain = Entity(id=1, type=EntityType.DOMAIN, value="example.com")
    email = Entity(id=2, type=EntityType.EMAIL, value="admin@example.com")

    rels = engine.build_relationships([domain, email], "test_plugin")
    assert len(rels) == 1
    assert rels[0].source_entity_id == 1
    assert rels[0].target_entity_id == 2
    assert rels[0].relationship_type.value == "registered_to"
