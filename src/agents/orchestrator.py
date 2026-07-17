"""
IncidentOps AI — Multi-Agent Orchestrator (Google ADK)

Runs the four-agent pipeline sequentially:
    1. TriageAgent    — classifies severity, identifies anomaly root cause
    2. ResearcherAgent — retrieves relevant runbooks via MCP server
    3. PlannerAgent   — drafts corrective action steps
    4. ReflectorAgent — self-critiques the plan for safety and completeness

Each agent is an ADK LlmAgent backed by Gemini. The IncidentState object
is the shared working memory; tools read from and write to it.

After reflection, the orchestrator returns the populated state to the CLI,
which then handles the human approval gate and simulation.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Callable

from src.core.state import IncidentState
from src.config import settings


# ---------------------------------------------------------------------------
# Agent factory helpers
# ---------------------------------------------------------------------------

def _make_triage_agent():
    """Build the Triage Agent with log and metric analysis tools."""
    from google.adk.agents import LlmAgent
    import src.skills.log_tools as lt
    import src.skills.metric_tools as mt

    return LlmAgent(
        name="triage_agent",
        model=settings.model_name,
        description=(
            "Senior SRE triage specialist. Analyses incident logs and metrics "
            "to classify severity and identify the root cause."
        ),
        instruction="""You are a senior Site Reliability Engineer performing incident triage.

Your task is to analyse the incident log and infrastructure metrics, then produce
a clear triage assessment.

Steps to follow:
1. Call get_incident_summary() to understand the incident context.
2. Call get_detected_anomalies() to see what the parser found.
3. Call get_infrastructure_metrics() to understand the metric state.
4. Call get_metric_severity_assessment() for threshold analysis.
5. Call get_log_error_events() to review specific error messages.
6. Call get_affected_services() to understand the blast radius.
7. Based on your analysis, call record_triage_finding(severity, summary) to
   record your severity classification and one-sentence root cause summary.

Be concise and precise. Your finding will be used by the Planner Agent.
""",
        tools=[
            lt.get_incident_summary,
            lt.get_detected_anomalies,
            lt.get_log_error_events,
            lt.get_affected_services,
            lt.get_redacted_log_sample,
            lt.record_triage_finding,
            mt.get_infrastructure_metrics,
            mt.get_metric_severity_assessment,
        ],
    )


def _make_researcher_agent():
    """Build the Researcher Agent with runbook retrieval tools."""
    from google.adk.agents import LlmAgent
    import src.skills.runbook_tools as rt
    import src.skills.log_tools as lt

    return LlmAgent(
        name="researcher_agent",
        model=settings.model_name,
        description=(
            "SRE knowledge researcher. Retrieves relevant operational runbooks "
            "from the MCP server to inform the corrective action plan."
        ),
        instruction="""You are an SRE researcher who retrieves operational runbooks.

Your task is to find the most relevant runbook for the current incident and
attach it to the incident context for the Planner Agent.

Steps to follow:
1. Call get_incident_summary() to understand the scenario.
2. Call list_available_runbooks() to see what's available.
3. Call fetch_runbook(scenario) using the scenario name from the summary.
   Use the exact scenario key from list_available_runbooks() output.
4. If you need just the recovery steps, call fetch_runbook_section(scenario, 'Recovery Steps').
5. Call get_current_runbooks() to confirm the runbook was recorded.

The runbook will be available to the Planner Agent via get_current_runbooks().
""",
        tools=[
            lt.get_incident_summary,
            rt.list_available_runbooks,
            rt.fetch_runbook,
            rt.fetch_runbook_section,
            rt.get_current_runbooks,
        ],
    )


def _make_planner_agent():
    """Build the Planner Agent with action plan submission tools."""
    from google.adk.agents import LlmAgent
    import src.skills.simulation_tools as st
    import src.skills.runbook_tools as rt
    import src.skills.log_tools as lt

    return LlmAgent(
        name="planner_agent",
        model=settings.model_name,
        description=(
            "SRE incident response planner. Drafts a structured corrective "
            "action plan using anomaly analysis and runbook guidance."
        ),
        instruction="""You are a senior SRE incident response planner.

Your task is to draft a concrete, prioritised corrective action plan for the
current incident based on the triage findings and runbook guidance.

Steps to follow:
1. Call get_planning_context() to get anomalies, metrics, and runbook references.
2. Call get_current_runbooks() to retrieve the runbook content.
3. Draft 3-5 concrete corrective action steps. Each step must be:
   - Specific and actionable (not vague)
   - Ordered by urgency (most urgent first)
   - Scoped to a specific target service
   - Assessed for risk (low/medium/high) and reversibility
4. Call submit_action_plan(summary, action_steps_json, confidence_score) to record
   your plan. Format action_steps_json as a JSON array:
   [
     {
       "step_number": 1,
       "description": "Specific action to take",
       "target_service": "service-name",
       "expected_impact": "What this will fix",
       "risk_level": "low",
       "is_reversible": true
     }
   ]
5. Set confidence_score between 0.0 and 1.0 based on how well the evidence
   supports the plan. Above 0.75 is required to avoid automatic escalation.

Prefer low-risk, reversible actions. Do not include destructive or irreversible
steps unless the runbook explicitly recommends them.
""",
        tools=[
            lt.get_incident_summary,
            st.get_planning_context,
            rt.get_current_runbooks,
            st.submit_action_plan,
        ],
    )


def _make_reflector_agent():
    """Build the Reflector Agent for self-critique and validation."""
    from google.adk.agents import LlmAgent
    import src.skills.simulation_tools as st
    import src.skills.log_tools as lt

    return LlmAgent(
        name="reflector_agent",
        model=settings.model_name,
        description=(
            "SRE plan reviewer. Critically evaluates the action plan for "
            "safety, completeness, and alignment with runbook guidance."
        ),
        instruction="""You are a critical SRE plan reviewer performing reflection.

Your task is to independently evaluate the proposed corrective action plan and
flag any issues before it is presented to the human operator.

Steps to follow:
1. Call get_plan_for_review() to retrieve the current plan.
2. Evaluate the plan against these criteria:
   a. SAFETY: Are any steps destructive or irreversible without clear justification?
   b. COMPLETENESS: Does the plan address all detected anomalies?
   c. ORDERING: Are steps in the right urgency order?
   d. RUNBOOK ALIGNMENT: Is the plan consistent with standard SRE procedures?
   e. CONFIDENCE: Is the confidence score appropriate given the evidence?
3. Call submit_reflection(notes, confidence_adjustment) with your findings:
   - notes: list of specific observations (validations AND concerns)
   - confidence_adjustment: e.g. +0.05 if plan is strong, -0.1 if there's a gap
4. If the plan has HIGH-RISK irreversible steps with no justification, or the
   confidence score is below 0.5, call flag_for_escalation(reason) instead.

Be rigorous but fair. The goal is to catch problems before human review,
not to block sound plans with excessive caution.
""",
        tools=[
            lt.get_incident_summary,
            lt.get_detected_anomalies,
            st.get_plan_for_review,
            st.submit_reflection,
            st.flag_for_escalation,
        ],
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class IncidentOrchestrator:
    """
    Runs the four-agent ADK pipeline for incident triage and response.

    Usage:
        orchestrator = IncidentOrchestrator(state)
        state = orchestrator.run(progress_callback=my_callback)
    """

    def __init__(self, state: IncidentState) -> None:
        self.state = state

    def run(
        self,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> IncidentState:
        """
        Execute the full agent pipeline synchronously.

        Args:
            progress_callback: Optional fn(agent_name, status) for UI updates.

        Returns:
            The updated IncidentState after all agents have run.
        """
        self._check_api_key()

        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

        return asyncio.run(self._run_pipeline(progress_callback))

    def _check_api_key(self) -> None:
        """Raise a clear error if no Google API key is configured."""
        key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not key:
            raise EnvironmentError(
                "No Google API key found.\n"
                "Set GOOGLE_API_KEY or GEMINI_API_KEY in your environment:\n"
                "  set GOOGLE_API_KEY=your-key-here\n"
                "Get a free key at: https://aistudio.google.com/apikey"
            )

    async def _run_pipeline(
        self,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> IncidentState:
        """Internal async pipeline execution."""
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        from google.genai import types as genai_types
        import src.skills.log_tools as lt
        import src.skills.metric_tools as mt
        import src.skills.runbook_tools as rt
        import src.skills.simulation_tools as st

        # Inject shared state into all skill modules
        for mod in (lt, mt, rt, st):
            mod.set_state(self.state)

        session_service = InMemorySessionService()

        agents = [
            ("triage_agent",      "Analysing logs and metrics...",     _make_triage_agent()),
            ("researcher_agent",  "Retrieving runbooks via MCP...",    _make_researcher_agent()),
            ("planner_agent",     "Drafting corrective action plan...", _make_planner_agent()),
            ("reflector_agent",   "Performing self-critique...",        _make_reflector_agent()),
        ]

        for agent_name, status_msg, agent in agents:
            if progress_callback:
                progress_callback(agent_name, status_msg)

            runner = Runner(
                agent=agent,
                app_name="incidentops",
                session_service=session_service,
            )

            session = session_service.create_session(
                app_name="incidentops",
                user_id="sre_operator",
            )

            # Build a context-rich prompt from the current incident state
            prompt = self._build_agent_prompt(agent_name)

            message = genai_types.Content(
                role="user",
                parts=[genai_types.Part(text=prompt)],
            )

            # Consume all events — the agent uses tools to update state
            async for event in runner.run_async(
                user_id="sre_operator",
                session_id=session.id,
                new_message=message,
            ):
                pass  # State mutations happen inside tool calls

            if progress_callback:
                progress_callback(agent_name, "done")

        return self.state

    def _build_agent_prompt(self, agent_name: str) -> str:
        """Build a context-rich starting prompt for each agent."""
        state = self.state
        inc = state.incident

        base = (
            f"Incident ID: {inc.id}\n"
            f"Scenario: {inc.scenario}\n"
            f"Current Severity: {inc.severity.value}\n"
            f"Status: {inc.status.value}\n"
            f"Anomalies detected: {len(state.anomalies)}\n"
            f"Runbooks retrieved: {len(state.runbooks_retrieved)}\n"
        )

        prompts = {
            "triage_agent": (
                f"You are handling a production incident.\n\n{base}\n"
                "Please triage this incident. Use your available tools to analyse "
                "the log anomalies and infrastructure metrics, then record your "
                "triage finding with severity classification and root cause summary."
            ),
            "researcher_agent": (
                f"The following incident has been triaged.\n\n{base}\n"
                "Please retrieve the relevant SRE runbook for this scenario "
                "from the runbook server using your tools."
            ),
            "planner_agent": (
                f"Triage and research are complete for this incident.\n\n{base}\n"
                "Please draft a corrective action plan with 3-5 specific, "
                "ordered, actionable steps based on the anomalies and runbook. "
                "Record your plan using submit_action_plan()."
            ),
            "reflector_agent": (
                f"A corrective action plan has been drafted for this incident.\n\n{base}\n"
                "Please critically review the plan for safety, completeness, "
                "and runbook alignment. Submit your reflection notes and any "
                "confidence adjustment."
            ),
        }
        return prompts.get(agent_name, f"Handle the incident: {inc.scenario}")
