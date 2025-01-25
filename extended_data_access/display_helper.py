import json


def pretty_print(who, what, json_str=None):
    """Unified pretty print for logs."""
    # Base message
    log_line = f"{who:<8}: {what}\n"
    
    if json_str is None:
        print(log_line)
        return

    try:
        if isinstance(json_str, (dict, list)):
            parsed_json = json_str
        else:
            parsed_json = json.loads(json_str)

        formatted_json = json.dumps(parsed_json, indent=4)
        padding = " " * (len(who) + 3)  
        indented_json = formatted_json.replace("\n", f"\n{padding}")
    except (json.JSONDecodeError, TypeError):
        indented_json = str(json_str)

    print(f"{log_line}\n{padding}{indented_json}\n")