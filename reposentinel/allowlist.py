from dataclasses import dataclass


@dataclass(frozen=True)
class RepositoryAllowlist:
    repositories: frozenset[str]

    @classmethod
    def from_values(cls, values: list[str]) -> "RepositoryAllowlist":
        return cls(frozenset(value.strip().lower() for value in values if value.strip()))

    def contains(self, full_name: str) -> bool:
        return full_name.strip().lower() in self.repositories

    def require(self, full_name: str) -> None:
        if not self.contains(full_name):
            raise PermissionError(f"Repository '{full_name}' is not in the configured allowlist")
