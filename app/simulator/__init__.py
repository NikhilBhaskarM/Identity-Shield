from app.config import SIMULATOR_MODE
from app.simulator.base import SimulatorAdapter
from app.simulator.mock import MockSimulator
from app.simulator.supplied import SuppliedSimulator

_mock_instance = MockSimulator()


def get_simulator() -> SimulatorAdapter:
    if SIMULATOR_MODE == "supplied":
        return SuppliedSimulator()
    return _mock_instance
