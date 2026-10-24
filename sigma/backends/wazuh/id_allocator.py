"""Deterministic Rule ID allocation for Wazuh backend."""

import hashlib
from typing import Dict, Optional, Set
from sigma.backends.wazuh.errors import WazuhIDCollisionError


class WazuhIDAllocator:
    """
    Deterministic rule ID allocator mapping Sigma rule identifiers to Wazuh SIDs.

    Wazuh custom/local rule range defaults to 100000 - 120000.
    """

    DEFAULT_MIN_ID: int = 100000
    DEFAULT_MAX_ID: int = 120000

    def __init__(
        self,
        min_id: int = DEFAULT_MIN_ID,
        max_id: int = DEFAULT_MAX_ID,
    ):
        if min_id >= max_id:
            raise ValueError(f"min_id ({min_id}) must be strictly less than max_id ({max_id})")
        self.min_id = min_id
        self.max_id = max_id
        self.span = max_id - min_id + 1

        # Track allocated IDs within the session: rule_id_str -> allocated_int_id
        self.allocated_by_rule: Dict[str, int] = {}
        # Reverse map: allocated_int_id -> rule_id_str
        self.allocated_sids: Dict[int, str] = {}

    def reset(self) -> None:
        """Clear allocated session IDs."""
        self.allocated_by_rule.clear()
        self.allocated_sids.clear()

    def allocate(self, rule_identifier: str, salt: int = 0) -> int:
        """
        Deterministically allocate a unique Wazuh rule ID for a given Sigma rule identifier.

        Args:
            rule_identifier: Rule UUID, rule ID, or rule title.
            salt: Salt offset for sub-rules / branch rules of the same parent rule.

        Returns:
            Deterministic integer SID within [min_id, max_id].
        """
        key = f"{rule_identifier}:{salt}"
        if key in self.allocated_by_rule:
            return self.allocated_by_rule[key]

        # Deterministic hashing with collision resolution
        attempt = 0
        max_attempts = min(self.span, 1000)

        while attempt < max_attempts:
            hash_input = f"{rule_identifier}:{salt}:{attempt}".encode("utf-8")
            digest = hashlib.sha256(hash_input).hexdigest()
            offset = int(digest, 16) % self.span
            candidate_id = self.min_id + offset

            # Check if this ID is already used by a DIFFERENT rule
            if candidate_id not in self.allocated_sids:
                self.allocated_sids[candidate_id] = key
                self.allocated_by_rule[key] = candidate_id
                return candidate_id

            # If it's already allocated to the exact same key, return it
            if self.allocated_sids[candidate_id] == key:
                return candidate_id

            attempt += 1

        raise WazuhIDCollisionError(rule_identifier, candidate_id)

    def allocate_subrule_id(self, parent_identifier: str, branch_index: int) -> int:
        """Allocate a deterministic ID for a child/branch rule in an OR-chain."""
        return self.allocate(parent_identifier, salt=1000 + branch_index)
