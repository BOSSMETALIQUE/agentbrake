"""Minimal AgentBrake config snippet — shown in the Loom demo intro."""

import agentbrake

agentbrake.init(
    allowed_tools=["search"],
    mode="remote",
)