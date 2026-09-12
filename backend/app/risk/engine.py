from typing import List, Tuple


def calculate_risk_level(score: int) -> str:
    if score <= 25:
        return "LOW"
    elif score <= 50:
        return "MEDIUM"
    elif score <= 75:
        return "HIGH"
    return "CRITICAL"


def compute_risk_score(
    base_points: int,
    factors: List[str],
    is_privileged_target: bool = False,
    is_external_connection: bool = False,
    is_after_hours: bool = False,
) -> Tuple[int, str, List[str]]:
    """
    Transparent additive risk scoring engine.
    Computes a score from 0 to 100, assigns a level (LOW/MEDIUM/HIGH/CRITICAL),
    and records the specific contributing risk factors.
    """
    total = base_points
    recorded_factors = list(factors)

    if is_privileged_target:
        total += 20
        recorded_factors.append("Privileged account targeted (+20)")

    if is_external_connection:
        total += 20
        recorded_factors.append("External unapproved destination (+20)")

    if is_after_hours:
        total += 15
        recorded_factors.append("Activity during non-business hours (+15)")

    # Clamp to 0-100
    clamped_score = max(0, min(100, total))
    level = calculate_risk_level(clamped_score)

    return clamped_score, level, recorded_factors
