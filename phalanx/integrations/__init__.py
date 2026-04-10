"""Framework integrations — thin adapters for popular agent frameworks.

Each adapter wraps the AgentHypervisor as middleware/hooks for:
- LangChain (callback handler)
- CrewAI (task decorator)
- OpenAI Agents SDK (RunHooks)

Zero extra dependencies — each adapter only imports its framework.
"""
