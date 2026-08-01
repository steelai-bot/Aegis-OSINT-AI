import logging
import re
import unicodedata

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

MAX_PERMUTATIONS = 40


class NamePermutatorPlugin(BasePlugin):
    """
    Generates username candidates from a person's full name.

    "Ivan Petrov" -> ivanpetrov, ivan.petrov, i.petrov, petrov.ivan, ipetrov,
    ivanp, ... The candidates are emitted as USERNAME entities so the pivot
    engine can feed them into username_enumeration in the next round.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="name_permutator",
            description=(
                "Derives likely username/handle permutations from a person's name "
                "for cross-platform enumeration."
            ),
            supported_entity_types=[TargetType.PERSON],
            tags=["identity", "username", "passive"],
            execution_cost=0.2,
            estimated_time=1,
        )

    @staticmethod
    def _transliterate(text: str) -> str:
        """Transliterate Cyrillic to Latin, strip accents/diacritics."""
        bg_map = {
            "а": "a",
            "б": "b",
            "в": "v",
            "г": "g",
            "д": "d",
            "е": "e",
            "ж": "zh",
            "з": "z",
            "и": "i",
            "й": "y",
            "к": "k",
            "л": "l",
            "м": "m",
            "н": "n",
            "о": "o",
            "п": "p",
            "р": "r",
            "с": "s",
            "т": "t",
            "у": "u",
            "ф": "f",
            "х": "h",
            "ц": "ts",
            "ч": "ch",
            "ш": "sh",
            "щ": "sht",
            "ъ": "a",
            "ь": "y",
            "ю": "yu",
            "я": "ya",
        }
        out = "".join(bg_map.get(ch, ch) for ch in text.lower())
        # Decompose remaining diacritics (é -> e) and drop non-ascii
        out = unicodedata.normalize("NFKD", out).encode("ascii", "ignore").decode()
        return out

    @classmethod
    def generate_permutations(cls, full_name: str) -> list[str]:
        parts = [cls._transliterate(p) for p in re.split(r"[\s,]+", full_name.strip()) if p]
        parts = [re.sub(r"[^a-z0-9]", "", p) for p in parts]
        parts = [p for p in parts if p]
        if not parts:
            return []

        first = parts[0]
        last = parts[-1] if len(parts) > 1 else ""
        candidates: set[str] = set()

        if last:
            fi, li = first[0], last[0]
            candidates.update(
                {
                    first + last,
                    first + "." + last,
                    first + "_" + last,
                    first + "-" + last,
                    last + first,
                    last + "." + first,
                    fi + last,
                    fi + "." + last,
                    fi + last + str(len(first)),
                    first + li,
                    first + "." + li,
                    first + last[0],
                    last + fi,
                    last + "." + fi,
                    first + last[-1],
                    fi + li,
                }
            )
            # Common year/birth suffixes on the most likely handles
            for base in (first + last, first + "." + last, fi + last):
                candidates.add(base + "1")
        else:
            candidates.add(first)

        # Keep only plausible usernames (3-30 chars)
        result = sorted(c for c in candidates if 3 <= len(c) <= 30)
        return result[:MAX_PERMUTATIONS]

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        permutations = self.generate_permutations(query)
        if not permutations:
            return []

        return [
            PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.PERSON,
                confidence=0.6,
                evidence=[
                    {
                        "type": "username_permutations",
                        "source_name": query.strip(),
                        "usernames": permutations,
                        "note": "Generated username candidates - feed into username_enumeration",
                    }
                ],
                raw={"query": query, "permutations": permutations},
            )
        ]
