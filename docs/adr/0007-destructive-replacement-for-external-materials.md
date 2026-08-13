# Resolve same-name file conflicts like a file system

**Status: Accepted for V1**

When an upload has the same logical filename as an existing file in the same Project, V1 will compare the original bytes. An identical upload reuses the existing file rather than creating a duplicate. If the bytes differ, the UI must ask the operator to **Replace**, **Create new version**, or cancel. **Replace** permanently deletes the old external-material bytes and stores the new file in its place. **Create new version** retains both files, with the new version becoming the current version; **Cancel** leaves the existing file unchanged and discards the incoming upload. Explicitly versioned filenames such as `report-v1.pdf` and `report-v2.pdf` are separate files and are both retained. This makes the destructive action explicit and follows familiar file-system semantics without silently losing research material.
