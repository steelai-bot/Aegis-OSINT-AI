import logging
import re

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone

    PHONENUMBERS_AVAILABLE = True
except ImportError:  # pragma: no cover - dependency is declared, defensive guard
    PHONENUMBERS_AVAILABLE = False


class PhoneLookupPlugin(BasePlugin):
    """
    Offline phone number intelligence via the phonenumbers library (Google libphonenumber).

    Validates and enriches phone numbers without any external API: E.164/international
    formatting, validity, region, carrier, timezones and line type. Also handles
    partial numbers (e.g. a fragment found in a breach) by reporting what can be
    inferred - digit count, possible country calling code and a normalized fragment
    suitable for cross-referencing against breach/stealer-log sources.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="phone_lookup",
            description=(
                "Validates and enriches phone numbers offline (region, carrier, timezone, "
                "line type) and normalizes partial numbers for breach cross-referencing."
            ),
            supported_entity_types=[TargetType.PHONE, TargetType.PERSON],
            tags=["phone", "identity", "passive"],
            execution_cost=0.5,
            estimated_time=1,
        )

    @staticmethod
    def _digits_only(value: str) -> str:
        return re.sub(r"\D", "", value)

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        if not PHONENUMBERS_AVAILABLE:
            logger.warning("phonenumbers library not installed - phone_lookup disabled")
            return []

        query_clean = query.strip()
        digits = self._digits_only(query_clean)
        if len(digits) < 4:
            return []

        evidence: list[dict] = []

        # 1. Try full parse (with and without assuming international format)
        parsed = None
        for candidate in (query_clean, f"+{digits}"):
            try:
                number = phonenumbers.parse(candidate, None)
                if phonenumbers.is_possible_number(number):
                    parsed = number
                    break
            except phonenumbers.NumberParseException:
                continue

        if parsed is not None:
            is_valid = phonenumbers.is_valid_number(parsed)
            region = phonenumbers.region_code_for_number(parsed)
            number_type = phonenumbers.number_type(parsed)
            type_name = {
                phonenumbers.PhoneNumberType.MOBILE: "mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
                phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
                phonenumbers.PhoneNumberType.VOIP: "voip",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
                phonenumbers.PhoneNumberType.PAGER: "pager",
                phonenumbers.PhoneNumberType.UAN: "uan",
                phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
            }.get(number_type, "unknown")

            evidence.append(
                {
                    "type": "phone_info",
                    "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                    "international": phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                    ),
                    "national": phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.NATIONAL
                    ),
                    "valid": is_valid,
                    "possible": True,
                    "country_code": parsed.country_code,
                    "region": region,
                    "location": geocoder.description_for_number(parsed, "en"),
                    "carrier": carrier.name_for_number(parsed, "en"),
                    "timezones": list(timezone.time_zones_for_number(parsed)),
                    "line_type": type_name,
                }
            )
        else:
            # 2. Partial number - report what can be inferred for cross-referencing
            partial: dict = {
                "type": "phone_partial",
                "fragment": digits,
                "digit_count": len(digits),
                "note": "Partial/unparseable number - normalized fragment for breach cross-referencing",
            }
            # A leading country calling code may still be identifiable
            for cc_len in (1, 2, 3):
                cc = digits[:cc_len]
                if cc and phonenumbers.region_codes_for_country_code(int(cc)):
                    partial["possible_country_code"] = int(cc)
                    partial["possible_regions"] = list(
                        phonenumbers.region_codes_for_country_code(int(cc))
                    )
                    break
            evidence.append(partial)

        if not evidence:
            return []

        confidence = 0.9 if evidence[0].get("valid") else 0.6
        return [
            PluginResponse(
                provider=self.metadata.name,
                entity_type=TargetType.PHONE,
                confidence=confidence,
                evidence=evidence,
                raw={"query": query_clean},
            )
        ]
