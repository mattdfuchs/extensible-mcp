# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the VC schema augmenter (search-side ToolFilter)."""

from __future__ import annotations

from extensible_mcp import SearchResult, ToolRecord

from extensible_mcp_vc.schema_augmenter import VCSchemaAugmenter


def _result(name: str, schema: dict | None = None) -> SearchResult:
    return SearchResult(
        tool=ToolRecord(
            name=name.split("__", 1)[1],
            qualified_name=name,
            description="some tool",
            input_schema=schema or {"type": "object", "properties": {"x": {"type": "string"}}},
            server_name=name.split("__", 1)[0],
        ),
        score=0.5,
    )


class TestVCSchemaAugmenter:
    def test_non_gated_passes_through_unchanged(self):
        aug = VCSchemaAugmenter(gated_tools=["payments__*"])
        r = _result("github__create_issue")
        out = aug.filter([r], "anything")
        assert out == [r]  # identity for non-gated

    def test_gated_tool_gets_vc_params(self):
        aug = VCSchemaAugmenter(gated_tools=["payments__*"])
        r = _result("payments__spend")
        out = aug.filter([r], "anything")
        schema = out[0].tool.input_schema
        assert "vc_request" in schema["properties"]
        assert "vc_authorization" in schema["properties"]
        assert "vc_request" in schema["required"]
        assert "vc_authorization" in schema["required"]
        # Original required parameter preserved (if any), original prop too
        assert "x" in schema["properties"]

    def test_augmentation_does_not_mutate_original(self):
        aug = VCSchemaAugmenter(gated_tools=["payments__*"])
        original_schema = {"type": "object", "properties": {"x": {"type": "string"}}}
        r = _result("payments__spend", schema=original_schema)
        aug.filter([r], "anything")
        assert "vc_request" not in original_schema["properties"]
        assert "required" not in original_schema

    def test_pattern_matching_with_wildcards(self):
        aug = VCSchemaAugmenter(gated_tools=["*__spend"])
        assert aug.is_gated("payments__spend")
        assert aug.is_gated("bank__spend")
        assert not aug.is_gated("payments__balance")

    def test_description_carries_obligation_text(self):
        aug = VCSchemaAugmenter(gated_tools=["payments__*"])
        r = _result("payments__spend")
        out = aug.filter([r], "anything")
        assert "Authorization required" in out[0].tool.description
        assert "request_action_vc" in out[0].tool.description
        assert "request_authorization_vc" in out[0].tool.description
