"""Optional provider integrations.

Each provider lives in its own module and is imported explicitly::

    from agentbrake.providers import cometapi

The AgentBrake core never imports from this package, so an integration can
depend on extra packages (e.g. ``openai``) without touching the base install.
"""
