# Run each Main Agent from its Project Context Directory

**Status: Accepted for V1**

The Web Console will launch a Project's Main Agent with that Project's Context Directory as the Claude Code working directory. The adapter will explicitly provide the Danus Main Agent contract, project state, and required capabilities instead of relying on Danus repository-root discovery of `CLAUDE.md`, `.mcp.json`, or skills. This makes the Project the natural file-access boundary and avoids exposing the repository root as the agent's default working context.
