# Keep strategic orchestration authority in the Main Agent

**Status: Accepted for V1**

The Project Main Agent retains the full Danus main-agent orchestration role: it may inspect the Project's state, memory, and Fact Graph, record strategy, and decide how to coordinate Workers. The Web Console only transports natural-language operator requests and renders outcomes; it does not independently approve, rewrite, or assign Worker work. Fact correctness remains governed by Danus' existing verifier boundary.
