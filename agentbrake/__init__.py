def init(api_key: str, allowed_tools: list = None, budget_usd: float = 5.0):
    """Initialize AgentBrake for the current run."""
    pass

def guard():
    """Decorator that wraps a tool execution function."""
    def decorator(fn):
        return fn
    return decorator