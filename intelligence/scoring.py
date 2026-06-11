def calculate_risk(abuse_data, is_port_scanning=False):
    """
    Risk Engine logic to calculate a final threat score (0-100) based on contextual intel.
    """
    score = 0
    abuse_confidence = abuse_data.get('abuseConfidenceScore', 0)
    country = abuse_data.get('countryCode', 'Unknown')
    usage_type = abuse_data.get('usageType', 'Unknown')

    # Base score from AbuseIPDB
    if abuse_confidence > 80:
        score += 50
    elif abuse_confidence > 50:
        score += 30
    elif abuse_confidence > 20:
        score += 10

    # GeoIP Context
    # Example logic: Higher risk applied to traffic from common adversarial geographies or anonymous VPS
    high_risk_countries = ["RU", "CN", "IR", "KP"]
    if country in high_risk_countries:
        score += 20

    # Infrastructure Context
    if "Tor" in usage_type or "VPN" in usage_type:
        score += 25
    elif "Data Center" in usage_type or "Hosting" in usage_type:
        score += 10

    # Behavioral Context (from our local sniffer)
    if is_port_scanning:
        score += 40

    # Cap score at 100
    final_score = min(score, 100)

    # Classify
    if final_score >= 90:
        classification = "CRITICAL"
    elif final_score >= 70:
        classification = "HIGH"
    elif final_score >= 40:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    return final_score, classification
