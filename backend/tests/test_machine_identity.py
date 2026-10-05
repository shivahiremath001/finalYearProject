import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Base, MachineRegistry, ConfigurationScan
from schemas import IngestRequest, CollectorData
import crud


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_upsert_machine_with_mac_and_guid(db_session):
    req1 = IngestRequest(
        host_id="WORKSTATION-01",
        os="Windows 11 Pro",
        asset_type="Workstation",
        ip="192.168.1.10",
        mac_address="00:11:22:33:44:55",
        machine_guid="11111111-2222-3333-4444-555555555555",
        data=CollectorData(),
    )

    machine = crud.upsert_machine(
        db_session, req1, ip="192.168.1.10", risk_score=25.0, risk_class="LOW RISK"
    )
    assert machine.hostname == "WORKSTATION-01"
    assert machine.ip_address == "192.168.1.10"
    assert machine.mac_address == "00:11:22:33:44:55"
    assert machine.machine_guid == "11111111-2222-3333-4444-555555555555"

    # Simulate IP change (DHCP lease renewal on another Wi-Fi network)
    req2 = IngestRequest(
        host_id="WORKSTATION-01",
        os="Windows 11 Pro",
        asset_type="Workstation",
        ip="10.0.0.88",
        mac_address="00:11:22:33:44:55",
        machine_guid="11111111-2222-3333-4444-555555555555",
        data=CollectorData(),
    )

    machine2 = crud.upsert_machine(
        db_session, req2, ip="10.0.0.88", risk_score=20.0, risk_class="LOW RISK"
    )
    # Must update the existing machine record, not create a duplicate
    assert machine2.id == machine.id
    assert machine2.ip_address == "10.0.0.88"
    assert machine2.mac_address == "00:11:22:33:44:55"


def test_find_machine_by_mac_or_guid(db_session):
    m = MachineRegistry(
        hostname="OLD-HOSTNAME",
        ip_address="192.168.1.50",
        mac_address="AA:BB:CC:DD:EE:FF",
        machine_guid="abcdef01-2345-6789-abcd-ef0123456789",
        status="ONLINE",
    )
    db_session.add(m)
    db_session.commit()

    # Found by GUID even if hostname changed
    found_guid = crud.find_machine(
        db_session,
        hostname="RENAMED-PC",
        machine_guid="abcdef01-2345-6789-abcd-ef0123456789",
    )
    assert found_guid is not None
    assert found_guid.id == m.id

    # Found by MAC even if hostname is different
    found_mac = crud.find_machine(
        db_session,
        hostname="ANOTHER-NAME",
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    assert found_mac is not None
    assert found_mac.id == m.id
