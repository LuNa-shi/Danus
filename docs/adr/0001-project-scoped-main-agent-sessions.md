# Use project-scoped Main Agent Sessions in the web console

**Status: Accepted for V1**

The web console will present one persistent Main Agent Session per Project, rather than exposing Danus' current single global interactive Main Agent directly. A session may be inactive between interactions and activated on demand; Workers remain independently runnable while it is inactive. The installed Claude Code CLI supports explicit session creation and resumption with a session UUID, but Danus' current `claude_code` strategy transport is intentionally stateless, so the web console will need an adapter rather than assuming this capability already exists in Danus. This proposal matches the desired GPT-like project experience and preserves project-level conversational isolation while leaving the existing Danus truth and worker layers behind an adapter.
