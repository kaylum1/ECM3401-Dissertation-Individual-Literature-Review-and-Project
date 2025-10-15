# server/score_calculator.py
"""
import re

def calculate_final_score(*scan_results):
    '''
    Extracts a numeric score from each scan result string (expected in the format '... score: X/10 ...'),
    computes the arithmetic average, and returns a final score (rounded to one decimal).
    
    If no valid scores are found, returns 0.
    '''
    scores = []
    for result in scan_results:
        # Look for a pattern like "score: X/10" (case-insensitive)
        match = re.search(r'(\d+(?:\.\d+)?)/10', result, re.IGNORECASE)
        if match:
            try:
                score = float(match.group(1))
                scores.append(score)
            except ValueError:
                continue
    if scores:
        average = sum(scores) / len(scores)
        return round(average, 1)
    else:
        return 0
"""


import re

def calculate_final_score(*scan_results, weights=None):
    """
    Extracts a numeric score from each scan result string (expected in the format 'Score: X/10 - ...'),
    rounds each score to a whole number between 1 and 10, and computes the weighted average if weights are provided.
    
    If no valid scores are found, returns 0.
    
    Parameters:
      *scan_results: Variable number of strings containing the scan scores.
      weights (list, optional): A list of weights corresponding to each scan result. If not provided,
                                all scans are weighted equally.
    
    Returns:
      int: The final weighted score (rounded to a whole number between 1 and 10).
    """
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
