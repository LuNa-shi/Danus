# Store project files in an isolated context directory and attach them to chat explicitly

**Status: Accepted for V1**

V1 will store each Project's uploaded documents in an isolated server-side Project Context Directory, represented logically as that Project's File Library. File transfer and updates are storage-only: they do not interrupt or activate an existing Main Agent Session. The Main Agent runs with the Project Context Directory as its working context and receives a specific file version as a Conversation Attachment only when the operator sends it together with a natural-language message. When an operator chooses **Create new version**, the old and new external-material files are retained; when they choose **Replace**, the old external-material bytes are deliberately deleted. This keeps project data physically separated while making Main Agent activation and file consideration explicit.
