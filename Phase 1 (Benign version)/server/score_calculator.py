# server/score_calculator.py

# === === === === === === === === === === === === === === ===
#This us the main code that dela with assigning a score for the differents scan

#A lot of the work here is off loaded to the different scan them selevs and server.py
# === === === === === === === === === === === === === === ===

#imports only need one
import re

def calculate_final_score(*scan_results, weights=None):

    scores = []
    # Regex matches "Score:" followed by a number (optionally with decimals), and an optional "/10"
    pattern = re.compile(r'Score:\s*(\d+(?:\.\d+)?)(?:/10)?', re.IGNORECASE)
    
    for result in scan_results:
        match = pattern.search(result)
        if match:
            try:
                score = float(match.group(1))
                # Round to nearest whole number and clamp between 1 and 10
                score = int(round(score))
                score = max(1, min(score, 10))
                scores.append(score)
            except ValueError:
                continue

    if not scores:
        return 0

    # If no weights are provided, assign equal weight to each score.
    if weights is None:
        weights = [1] * len(scores)
    if len(weights) != len(scores):
        raise ValueError("The number of weights must match the number of scan results.")

    weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
    total_weight = sum(weights)
    final_score = int(round(weighted_sum / total_weight))
    final_score = max(1, min(final_score, 10))
    return final_score
