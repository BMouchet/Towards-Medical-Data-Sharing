import json


def pretty_print(who, what, json_str=None):
    """Unified pretty print for logs."""
    # Base message
    log_line = f"{who:<10}: {what}"
    
    if json_str is None:
        # Simple log message without JSON
        print(log_line)
        return

    try:
        # Handle input as either JSON string or dict
        if isinstance(json_str, (dict, list)):
            parsed_json = json_str
        else:
            parsed_json = json.loads(json_str)

        # Format the JSON block
        formatted_json = json.dumps(parsed_json, indent=4)
        # Align JSON block under the message
        padding = " " * (len(who) + 3)  # Adjust for WHO label
        indented_json = formatted_json.replace("\n", f"\n{padding}")
    except (json.JSONDecodeError, TypeError):
        # Fallback to raw string if JSON is invalid
        indented_json = str(json_str)

    # Print message and aligned JSON block
    print(f"{log_line}\n{padding}{indented_json}\n")