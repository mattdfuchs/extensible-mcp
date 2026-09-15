# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Search-side ToolFilter that surfaces the VC obligation in tool schemas.

When a gated tool comes back from ``search_tools``, the LLM should see two
extra required parameters (``vc_request`` and ``vc_authorization``) and a
short description of how to obtain them. Rewriting the schema here keeps the
obligation discoverable through the same channel as the rest of the tool's
input contract.
"""

from __future__ import annotations

import fnmatch
import logging
from copy import deepcopy
from typing import Any

from extensible_mcp import SearchResult, ToolRecord

logger = logging.getLogger("extensible_mcp_vc.augmenter")

VC_BUNDLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": (
        "Signed VC bundle returned by request_action_vc or "
        "request_authorization_vc."
    ),
    "properties": {
        "token": {
            "type": "string",
            "description": "Compact JWS string for the signed VC.",
        },
        "membership": {
            "type": "string",
            "description": (
                "Compact JWS string for the signer's FamilyMembership VC."
            ),
        },
    },
    "required": ["token", "membership"],
}

_GATED_DESCRIPTION = (
    "\n\n**Authorization required.** Before calling this tool, obtain a "
    "signed request VC from `request_action_vc` and a signed authorization "
    "VC from `request_authorization_vc`. Pass them as `vc_request` and "
    "`vc_authorization` arguments."
)

_OPTIONAL_AUTH_DESCRIPTION = (
    "\n\n**Conditional authorization.** Always obtain a signed request VC "
    "from `request_action_vc` and pass it as `vc_request` (this is the "
    "originator's consent). Additionally, for higher-impact calls (the "
    "downstream policy decides where the threshold is — typically a dollar "
    "amount), obtain a signed authorization VC from `request_authorization_vc` "
    "and pass it as `vc_authorization`. If the policy rejects the call for "
    "missing authorization, retry with the parent's VC."
)


class VCSchemaAugmenter:
    def __init__(
        self,
        gated_tools: list[str],
        optional_authorization_tools: list[str] | None = None,
    ) -> None:
        self._gated_patterns: list[str] = list(gated_tools)
        self._optional_auth_patterns: list[str] = list(
            optional_authorization_tools or []
        )

    def is_gated(self, qualified_name: str) -> bool:
        return any(fnmatch.fnmatch(qualified_name, p) for p in self._gated_patterns)

    def is_optional_auth(self, qualified_name: str) -> bool:
        return any(
            fnmatch.fnmatch(qualified_name, p)
            for p in self._optional_auth_patterns
        )

    def filter(
        self, results: list[SearchResult], query: str
    ) -> list[SearchResult]:
        out: list[SearchResult] = []
        for r in results:
            name = r.tool.qualified_name
            if self.is_gated(name):
                logger.info(
                    "[VC] augmenting schema for gated tool %r: vc_request and "
                    "vc_authorization both required (search query: %r)",
                    name,
                    query,
                )
                out.append(
                    SearchResult(
                        tool=self._augment(r.tool, optional_auth=False),
                        score=r.score,
                    )
                )
            elif self.is_optional_auth(name):
                logger.info(
                    "[VC] augmenting schema for optional-auth tool %r: "
                    "vc_request required, vc_authorization optional "
                    "(search query: %r)",
                    name,
                    query,
                )
                out.append(
                    SearchResult(
                        tool=self._augment(r.tool, optional_auth=True),
                        score=r.score,
                    )
                )
            else:
                out.append(r)
        return out

    def _augment(self, tool: ToolRecord, *, optional_auth: bool) -> ToolRecord:
        schema = deepcopy(tool.input_schema) if tool.input_schema else {}
        schema.setdefault("type", "object")
        properties = schema.setdefault("properties", {})
        properties["vc_request"] = deepcopy(VC_BUNDLE_SCHEMA)
        properties["vc_authorization"] = deepcopy(VC_BUNDLE_SCHEMA)
        required = list(schema.get("required", []))
        if "vc_request" not in required:
            required.append("vc_request")
        if not optional_auth and "vc_authorization" not in required:
            required.append("vc_authorization")
        schema["required"] = required
        description_suffix = (
            _OPTIONAL_AUTH_DESCRIPTION if optional_auth else _GATED_DESCRIPTION
        )
        return ToolRecord(
            name=tool.name,
            qualified_name=tool.qualified_name,
            description=tool.description + description_suffix,
            input_schema=schema,
            server_name=tool.server_name,
            embedding_text=tool.embedding_text,
        )
