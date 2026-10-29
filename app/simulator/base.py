"""Simulator adapter base class."""


class SimulatorAdapter:
    def step_up(self, identity_id: str, session_id: str | None = None) -> str:
        raise NotImplementedError

    def restrict(self, identity_id: str, scope: str = "temporary") -> str:
        raise NotImplementedError

    def revoke(self, identity_id: str, session_id: str | None = None) -> str:
        raise NotImplementedError
