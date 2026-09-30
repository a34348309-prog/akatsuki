from typing import List, Set, Tuple
from app.models.event import UniversalEvent


class DeduplicationService:
    """
    SIH PS 26156 Deduplication Stage.
    Identifies duplicate events using deterministic SHA-256 fingerprinting.
    Preserves raw evidence integrity while returning unique normalized streams.
    """
    def deduplicate(self, events: List[UniversalEvent]) -> Tuple[List[UniversalEvent], int, int]:
        """
        Deduplicates a list of normalized events.
        Returns: (unique_events, total_detected, duplicates_removed_count)
        """
        seen_hashes: Set[str] = set()
        unique_events: List[UniversalEvent] = []
        duplicates_removed = 0

        for event in events:
            # Deterministic SHA-256 hash check
            fingerprint = event.event_hash
            if fingerprint in seen_hashes:
                duplicates_removed += 1
            else:
                seen_hashes.add(fingerprint)
                unique_events.append(event)

        return unique_events, len(events), duplicates_removed
