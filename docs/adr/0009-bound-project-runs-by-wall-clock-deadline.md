# Bound each Project Run by an enforced wall-clock deadline

**Status: Accepted for V1**

Every Project Run will have an operator-selected duration, such as 12 hours, converted at start into an absolute Run Deadline enforced through Danus' existing project deadline mechanism. Main Agent sessions remain on-demand rather than running continuously for the entire duration. The operator may request a graceful stop before the deadline; stopping affects only that Project and does not erase its persisted research state. Per-turn Main Agent timeouts and per-round Worker timeouts remain separate controls, while monetary/API limits are secondary and will only be exposed when the configured runtime can report and enforce them reliably.
