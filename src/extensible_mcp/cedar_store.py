# Copyright (c) 2026 Matthew Fuchs
# SPDX-License-Identifier: Apache-2.0

"""The Cedar entity store, formed per call from the fetch plan's ``entities``
block.

Cedar decides over a request head (principal, action, resource), a
``context`` record and an **entity store**: the entities the head names,
their attributes, and their parent edges, whose transitive closure is what
``in`` tests. The proxy's bundle format assembles one closed input per call
from declared sources; this module is the rule for turning that input into
the store, and the rule is a *declaration* the bundle ships, never an
inspection of the data:

- The plan's top-level ``entities`` block names the head's two entity types
  and where each id comes from (``caller.sub`` or ``package`` by default, or
  an input field holding an entity reference), the manifest fields **moved**
  from ``context`` onto each entity as attributes, the fields whose values
  are entity ``references`` (wrapped in Cedar's ``__entity`` form, since
  Cedar reads a bare ``{"type", "id"}`` record as an entity only under a
  schema, and the schema stays out of ``is_authorized``), the ``memberships``
  (a field holding the **closed** ancestor set of the principal or the
  resource, from which that entity's parents are formed), and ``nested``
  attributes placed on a referenced entity.
- A bundle that ships no block gets the store it always had: ``Caller`` and
  ``Server`` with no attributes and no parents, so every earlier bundle
  decides as before.
- A store that cannot be formed *as declared* -- an id field absent, a
  reference of another type, a membership field that is not a list of
  references -- is :class:`StoreFormationError`, a fault distinct from a
  denial. Nothing checks the store per call by design (the toolchain
  measured Cedar's schema-checked store parse as too strict for manifests
  with open objects), so the declaration is the check.

Hierarchy membership is **data**, read the way Cedar itself reads it: ``x in
t`` is ``x == t`` or ``t`` in ``x``'s ancestor set, the transitive closure of
the store's parent edges, which Cedar computes when the store is built (and
refuses on a cycle). A membership field carries the closure already; Cedar
closing it again is idempotent. No engine walks a chain at evaluation time,
and neither does this module.

The one load-time check that is this module's rather than the validator's is
:func:`check_hierarchy`: with a schema beside the policy, every ``in`` whose
relation the schema's ``memberOfTypes`` cannot reach is refused by name. The
validator types such an ``in`` as ``false`` and reports nothing, so a rule
over an undeclared relation would be silently inert -- the hazard the
schema-less refusal of ``in`` exists for, in a form the schema lets the
loader name exactly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Any

from .wasm_policy import PolicyEvaluationError

ENTITIES_KEY = "entities"
SCHEMA_FILE = "schema.json"

DEFAULT_PRINCIPAL_TYPE = "Caller"
DEFAULT_RESOURCE_TYPE = "Server"
#: The principal's id when the input carries no caller: a head a rule may
#: name, and one a rule testing ``principal == Caller::"<sub>"`` never matches.
ANONYMOUS_ID = "anonymous"

ID_FROM_CALLER = "caller"
ID_FROM_PACKAGE = "package"
ID_FROM_INPUT = "input"

#: Cedar's ``__entity`` escape: the one key the JSON reader takes as an entity
#: reference whatever schema it has or lacks. The loader writes it; an input
#: that carries it is refused (see ``cedar_policy.RESERVED_KEY_PREFIX``).
ENTITY_ESCAPE = "__entity"

_BLOCK_KEYS = frozenset({"principal", "resource", "references", "memberships", "nested"})
_HEAD_KEYS = frozenset({"type", "id", "attributes"})
_ID_KEYS = frozenset({"from", "field"})
_REFERENCE_KEYS = frozenset({"field", "type", "set"})
_MEMBERSHIP_KEYS = frozenset({"field", "of"})
_NESTED_KEYS = frozenset({"field", "via", "as"})
_SUBJECTS = frozenset({"principal", "resource"})

#: A Cedar entity type name, namespaced or not: ``User``, ``N::Billing::Invoice``.
TYPE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
_ATTR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PlacementError(ValueError):
    """An ``entities`` block the loader refuses: malformed, placing a field
    twice, or declaring a shape this release does not form (a membership of
    an attribute subject, a nested attribute via a set). Raised at load, so
    no such bundle governs a call."""


class StoreFormationError(PolicyEvaluationError):
    """The declared store could not be formed from this call's validated
    input. A fault, never a denial: the manifest admitted an input the block
    cannot place, so one of the two declarations is wrong and the call fails
    closed with the reason rather than deciding over a store the bundle did
    not mean."""


def entity_literal(entity_type: str, entity_id: str) -> str:
    """``Type::"id"`` with the id escaped as a Cedar string literal. A control
    character is refused rather than escaped: no tool, subject or package name
    legitimately carries one, and Cedar's escape forms differ from JSON's."""
    check_id(entity_type, entity_id)
    escaped = entity_id.replace("\\", "\\\\").replace('"', '\\"')
    return f'{entity_type}::"{escaped}"'


def check_id(entity_type: str, entity_id: str) -> None:
    if any(ord(ch) < 0x20 or ch == "\x7f" for ch in entity_id):
        raise PolicyEvaluationError(
            f"{entity_type} id {entity_id!r} carries a control character"
        )


# --------------------------------------------------------------------------- #
# The declaration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Head:
    """One of the request's two entities: its type, where its id comes from,
    and the manifest fields moved onto it as attributes."""

    type: str
    id_from: str
    id_field: str | None = None
    attributes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Reference:
    """A manifest field whose value is an entity reference (or, with ``set``,
    a list of them), to be wrapped in the ``__entity`` escape wherever it
    lands -- on an entity or in ``context``."""

    field: str
    type: str
    set: bool


@dataclass(frozen=True)
class Membership:
    """A manifest field holding the closed ancestor set of ``of`` (the
    principal or the resource), as a list of entity references. The entity's
    parents are formed from it; an absent field means no parents of that
    kind, which is the correct answer once the store is real: not a member."""

    field: str
    of: str


@dataclass(frozen=True)
class Nested:
    """A manifest field placed on the entity the reference at ``via`` names,
    as its attribute ``as_`` -- a one-hop entity attribute the importer
    flattened into the input (``owner_blocked`` read as ``resource.owner.blocked``)."""

    field: str
    via: str
    as_: str


@dataclass(frozen=True)
class EntityPlacement:
    """The parsed ``entities`` block, or the default when a bundle ships none."""

    principal: Head
    resource: Head
    references: tuple[Reference, ...] = ()
    memberships: tuple[Membership, ...] = ()
    nested: tuple[Nested, ...] = ()
    #: Whether a block was shipped at all, for docs and diagnostics.
    declared: bool = dc_field(default=False, compare=False)

    @classmethod
    def default(cls) -> "EntityPlacement":
        return cls(
            principal=Head(DEFAULT_PRINCIPAL_TYPE, ID_FROM_CALLER, "sub"),
            resource=Head(DEFAULT_RESOURCE_TYPE, ID_FROM_PACKAGE),
        )

    def placed_fields(self) -> frozenset[str]:
        """The manifest fields that leave ``context``: each head's attributes,
        an ``input``-sourced id, the membership fields and the nested ones.
        A reference field stays where it is and is only wrapped."""
        out: set[str] = set()
        for head in (self.principal, self.resource):
            out.update(head.attributes)
            if head.id_from == ID_FROM_INPUT and head.id_field:
                out.add(head.id_field)
        out.update(m.field for m in self.memberships)
        out.update(n.field for n in self.nested)
        return frozenset(out)

    def referenced_fields(self) -> frozenset[str]:
        return frozenset(r.field for r in self.references)

    def subject_type(self, subject: str) -> str:
        return self.principal.type if subject == "principal" else self.resource.type


def parse_placement(block: Any, where: str) -> EntityPlacement:
    """The block as the plan carries it, checked. ``None`` is the default
    placement; anything else must be the declared shape exactly -- an unknown
    key, a field placed twice, or a subject this release cannot form is
    refused by name rather than ignored, because a placement that is half
    read decides over a store the bundle did not mean."""
    if block is None:
        return EntityPlacement.default()
    if not isinstance(block, dict):
        raise PlacementError(f"{where}: 'entities' must be an object")
    unknown = set(block) - _BLOCK_KEYS
    if unknown:
        raise PlacementError(f"{where}: 'entities' has unknown key(s) {sorted(unknown)}")

    principal = _parse_head(
        block.get("principal"), "principal", where,
        default=EntityPlacement.default().principal,
        id_sources=(ID_FROM_CALLER, ID_FROM_INPUT),
    )
    resource = _parse_head(
        block.get("resource"), "resource", where,
        default=EntityPlacement.default().resource,
        id_sources=(ID_FROM_PACKAGE, ID_FROM_INPUT),
    )

    placed: dict[str, str] = {}

    def place(field_name: str, as_what: str) -> None:
        if field_name in placed:
            raise PlacementError(
                f"{where}: field {field_name!r} is placed twice ({placed[field_name]} "
                f"and {as_what}); a field leaves context for exactly one place"
            )
        placed[field_name] = as_what

    for head, label in ((principal, "principal"), (resource, "resource")):
        for a in head.attributes:
            place(a, f"an attribute of the {label}")
        if head.id_from == ID_FROM_INPUT:
            place(head.id_field or "", f"the {label}'s id")

    references = tuple(
        _parse_reference(r, where) for r in _as_list(block.get("references"), "references", where)
    )
    ref_fields = [r.field for r in references]
    if len(set(ref_fields)) != len(ref_fields):
        raise PlacementError(f"{where}: 'references' lists a field twice")
    by_field = {r.field: r for r in references}

    memberships = tuple(
        _parse_membership(m, where) for m in _as_list(block.get("memberships"), "memberships", where)
    )
    for m in memberships:
        place(m.field, f"the {m.of}'s memberships")
        if m.field in by_field:
            raise PlacementError(
                f"{where}: membership field {m.field!r} is also listed under "
                "'references'; a membership field leaves context and references"
            )

    nested = tuple(
        _parse_nested(n, where) for n in _as_list(block.get("nested"), "nested", where)
    )
    for n in nested:
        place(n.field, f"attribute {n.as_!r} of the entity at {n.via!r}")
        via = by_field.get(n.via)
        if via is None:
            raise PlacementError(
                f"{where}: nested field {n.field!r} is placed via {n.via!r}, which "
                "'references' does not list; the loader places a nested attribute "
                "on the entity a declared reference names"
            )
        if via.set:
            raise PlacementError(
                f"{where}: nested field {n.field!r} is placed via {n.via!r}, a set of "
                "references; an attribute has one entity to land on"
            )

    for head, label in ((principal, "principal"), (resource, "resource")):
        if head.id_from == ID_FROM_INPUT:
            ref = by_field.get(head.id_field or "")
            if ref is None or ref.set or ref.type != head.type:
                raise PlacementError(
                    f"{where}: the {label}'s id comes from input field "
                    f"{head.id_field!r}, which 'references' must list as a single "
                    f"reference of type {head.type!r}"
                )

    return EntityPlacement(
        principal=principal,
        resource=resource,
        references=references,
        memberships=memberships,
        nested=nested,
        declared=True,
    )


def _as_list(value: Any, key: str, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PlacementError(f"{where}: 'entities.{key}' must be a list")
    return value


def _type_name(value: Any, what: str, where: str) -> str:
    if not isinstance(value, str) or not TYPE_NAME.match(value):
        raise PlacementError(
            f"{where}: {what} must be a Cedar entity type name, got {value!r}"
        )
    return value


def _field_name(value: Any, what: str, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise PlacementError(f"{where}: {what} must name a manifest field, got {value!r}")
    return value


def _parse_head(
    spec: Any, label: str, where: str, *, default: Head, id_sources: tuple[str, ...]
) -> Head:
    if spec is None:
        return default
    if not isinstance(spec, dict):
        raise PlacementError(f"{where}: 'entities.{label}' must be an object")
    unknown = set(spec) - _HEAD_KEYS
    if unknown:
        raise PlacementError(
            f"{where}: 'entities.{label}' has unknown key(s) {sorted(unknown)}"
        )
    entity_type = _type_name(spec.get("type"), f"'entities.{label}.type'", where)
    id_spec = spec.get("id")
    if not isinstance(id_spec, dict) or set(id_spec) - _ID_KEYS:
        raise PlacementError(
            f"{where}: 'entities.{label}.id' must be an object with 'from' and, "
            "for 'caller' or 'input', 'field'"
        )
    id_from = id_spec.get("from")
    if id_from not in id_sources:
        raise PlacementError(
            f"{where}: 'entities.{label}.id.from' is {id_from!r}; a {label}'s id comes "
            f"from one of {list(id_sources)}"
        )
    id_field: str | None = None
    if id_from == ID_FROM_PACKAGE:
        if "field" in id_spec:
            raise PlacementError(
                f"{where}: 'entities.{label}.id' from 'package' takes no 'field'"
            )
    else:
        id_field = _field_name(id_spec.get("field"), f"'entities.{label}.id.field'", where)
    attrs = spec.get("attributes", [])
    if not isinstance(attrs, list) or not all(
        isinstance(a, str) and _ATTR_NAME.match(a) for a in attrs
    ):
        raise PlacementError(
            f"{where}: 'entities.{label}.attributes' must be a list of attribute names"
        )
    if len(set(attrs)) != len(attrs):
        raise PlacementError(f"{where}: 'entities.{label}.attributes' lists a field twice")
    return Head(entity_type, id_from, id_field, tuple(attrs))


def _parse_reference(spec: Any, where: str) -> Reference:
    if not isinstance(spec, dict) or set(spec) != _REFERENCE_KEYS:
        raise PlacementError(
            f"{where}: each 'entities.references' entry is {{field, type, set}}"
        )
    if not isinstance(spec["set"], bool):
        raise PlacementError(f"{where}: a reference's 'set' must be a boolean")
    return Reference(
        _field_name(spec["field"], "a reference's 'field'", where),
        _type_name(spec["type"], "a reference's 'type'", where),
        spec["set"],
    )


def _parse_membership(spec: Any, where: str) -> Membership:
    if not isinstance(spec, dict) or set(spec) != _MEMBERSHIP_KEYS:
        raise PlacementError(
            f"{where}: each 'entities.memberships' entry is {{field, of}}"
        )
    of = spec["of"]
    if of not in _SUBJECTS:
        raise PlacementError(
            f"{where}: membership 'of' is {of!r}; this release forms the hierarchy "
            "of the principal and the resource only, not of an attribute subject"
        )
    return Membership(_field_name(spec["field"], "a membership's 'field'", where), of)


def _parse_nested(spec: Any, where: str) -> Nested:
    if not isinstance(spec, dict) or set(spec) != _NESTED_KEYS:
        raise PlacementError(
            f"{where}: each 'entities.nested' entry is {{field, via, as}}"
        )
    as_ = spec["as"]
    if not isinstance(as_, str) or not _ATTR_NAME.match(as_):
        raise PlacementError(f"{where}: a nested entry's 'as' must be an attribute name")
    return Nested(
        _field_name(spec["field"], "a nested entry's 'field'", where),
        _field_name(spec["via"], "a nested entry's 'via'", where),
        as_,
    )


def check_placement_against_plan(
    placement: EntityPlacement, plan: dict[str, Any], where: str
) -> None:
    """Every field the block names must be one the plan assembles and emits.
    A placed field no entry produces could never leave ``context``, so the
    policy's ``has`` guard over it would be a sentence about nothing."""
    emitted = {
        e.get("field")
        for e in plan.get("entries") or []
        if isinstance(e, dict) and e.get("emit", True) is not False
    }
    missing = sorted(
        (placement.placed_fields() | placement.referenced_fields()) - emitted
    )
    if missing:
        raise PlacementError(
            f"{where}: 'entities' places field(s) {missing}, which no emitted "
            "fetch-plan entry assembles"
        )
    # A `caller` id source is not checked against the plan: it reads the
    # `caller` object when an entry assembles one and is `anonymous` when none
    # does, which is a head a rule may name (and one `principal == Caller::"x"`
    # never matches), exactly as for a bundle with no block at all.


# --------------------------------------------------------------------------- #
# The store, per call
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FormedRequest:
    """One call's request as Cedar is handed it: the head as entity literals,
    the context the placed fields have left, and the store."""

    head: dict[str, str]
    context: dict[str, Any]
    entities: list[dict[str, Any]]


def form_store(
    input_obj: dict[str, Any], placement: EntityPlacement, package: str
) -> FormedRequest:
    """Form the request from the validated input, as the block says.

    The input is copied, never mutated. Each placed field is popped from the
    copy onto its entity; a field the input lacks stays absent on the
    entity, so the policy's ``has`` guards decide exactly as they did over
    ``context``. Reference values are wrapped by the block, never by
    inspecting shapes: a record that happens to carry ``type`` and ``id`` at
    an unlisted field is a record.
    """
    rest = dict(input_obj)
    refs = {r.field: r for r in placement.references}

    def ref_of(where: str, value: Any, expected: str) -> dict[str, str]:
        if (
            not isinstance(value, dict)
            or set(value) != {"type", "id"}
            or not isinstance(value["type"], str)
            or not isinstance(value["id"], str)
        ):
            raise StoreFormationError(
                f"the declared store cannot be formed: {where} is not an entity "
                f"reference {{type, id}}"
            )
        if value["type"] != expected:
            raise StoreFormationError(
                f"the declared store cannot be formed: {where} references a "
                f"{value['type']!r}, not the declared {expected!r}"
            )
        check_id(value["type"], value["id"])
        return {"type": value["type"], "id": value["id"]}

    def wrap(field_name: str, value: Any) -> Any:
        ref = refs.get(field_name)
        if ref is None:
            return value
        if ref.set:
            if not isinstance(value, list):
                raise StoreFormationError(
                    f"the declared store cannot be formed: reference set "
                    f"{field_name!r} is not a list"
                )
            return [
                {ENTITY_ESCAPE: ref_of(f"{field_name}[{i}]", v, ref.type)}
                for i, v in enumerate(value)
            ]
        return {ENTITY_ESCAPE: ref_of(field_name, value, ref.type)}

    def uid_of(head: Head, label: str) -> dict[str, str]:
        if head.id_from == ID_FROM_PACKAGE:
            check_id(head.type, package)
            return {"type": head.type, "id": package}
        if head.id_from == ID_FROM_CALLER:
            caller = rest.get("caller")
            sub = caller.get(head.id_field) if isinstance(caller, dict) else None
            if isinstance(sub, str) and sub:
                check_id(head.type, sub)
                return {"type": head.type, "id": sub}
            return {"type": head.type, "id": ANONYMOUS_ID}
        # input: the field *is* the entity, and leaves context.
        if head.id_field not in rest:
            raise StoreFormationError(
                f"the declared store cannot be formed: the {label}'s id field "
                f"{head.id_field!r} is absent from the input"
            )
        return ref_of(f"the {label}'s id field {head.id_field!r}", rest.pop(head.id_field), head.type)

    uids = {"principal": uid_of(placement.principal, "principal"),
            "resource": uid_of(placement.resource, "resource")}
    attrs: dict[str, dict[str, Any]] = {"principal": {}, "resource": {}}
    for subject, head in (("principal", placement.principal), ("resource", placement.resource)):
        for a in head.attributes:
            if a in rest:
                attrs[subject][a] = wrap(a, rest.pop(a))

    parents: dict[str, list[dict[str, str]]] = {"principal": [], "resource": []}
    for m in placement.memberships:
        if m.field not in rest:
            continue
        value = rest.pop(m.field)
        if not isinstance(value, list):
            raise StoreFormationError(
                f"the declared store cannot be formed: membership field {m.field!r} "
                "is not a list of entity references"
            )
        for i, v in enumerate(value):
            if (
                not isinstance(v, dict) or set(v) != {"type", "id"}
                or not isinstance(v["type"], str) or not isinstance(v["id"], str)
            ):
                raise StoreFormationError(
                    f"the declared store cannot be formed: {m.field}[{i}] is not an "
                    "entity reference {type, id}"
                )
            check_id(v["type"], v["id"])
            parents[m.of].append({"type": v["type"], "id": v["id"]})

    # Nested attributes land on the entity a reference names; the reference
    # is looked up where it was placed (an attribute, or still in context).
    nested_entities: dict[tuple[str, str], dict[str, Any]] = {}
    for n in placement.nested:
        if n.field not in rest:
            continue
        via_value = None
        for bag in (attrs["principal"], attrs["resource"]):
            if n.via in bag:
                via_value = bag[n.via][ENTITY_ESCAPE]
        if via_value is None and n.via in rest:
            via_value = ref_of(n.via, rest[n.via], refs[n.via].type)
        if via_value is None:
            raise StoreFormationError(
                f"the declared store cannot be formed: nested field {n.field!r} is "
                f"present but its entity reference {n.via!r} is absent"
            )
        key = (via_value["type"], via_value["id"])
        entry = nested_entities.setdefault(
            key, {"uid": dict(via_value), "attrs": {}, "parents": []}
        )
        entry["attrs"][n.as_] = wrap(n.field, rest.pop(n.field))

    for field_name in list(rest):
        if field_name in refs:
            rest[field_name] = wrap(field_name, rest[field_name])

    entities: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for subject in ("principal", "resource"):
        uid = uids[subject]
        key = (uid["type"], uid["id"])
        if key in seen:
            # The same entity at both heads: one entry, both attribute sets.
            seen[key]["attrs"].update(attrs[subject])
            seen[key]["parents"].extend(parents[subject])
            continue
        entry = {"uid": uid, "attrs": attrs[subject], "parents": parents[subject]}
        seen[key] = entry
        entities.append(entry)
    for key, entry in nested_entities.items():
        if key in seen:
            seen[key]["attrs"].update(entry["attrs"])
        else:
            entities.append(entry)

    tool = rest.get("tool")
    action = entity_literal("Action", tool) if isinstance(tool, str) and tool else 'Action::"call"'
    head = {
        "principal": entity_literal(uids["principal"]["type"], uids["principal"]["id"]),
        "action": action,
        "resource": entity_literal(uids["resource"]["type"], uids["resource"]["id"]),
    }
    return FormedRequest(head=head, context=rest, entities=entities)


# --------------------------------------------------------------------------- #
# The schema, at load
# --------------------------------------------------------------------------- #


class HierarchyError(ValueError):
    """An ``in`` the schema cannot make true: its relation is not reachable
    through ``memberOfTypes`` from the subject's type, or its subject is one
    this release does not form a hierarchy for. Refused at load."""


def member_of_graph(schema: dict[str, Any]) -> dict[str, frozenset[str]]:
    """Each entity type's declared parent types, names fully qualified: a
    bare name inside namespace ``N`` is ``N::<name>`` when ``N`` declares it,
    as Cedar resolves it, and itself otherwise."""
    graph: dict[str, set[str]] = {}
    for ns, body in schema.items():
        if not isinstance(body, dict):
            continue
        types = body.get("entityTypes") or {}
        declared = {_qualify(ns, t) for t in types}
        for t, spec in types.items():
            q = _qualify(ns, t)
            parents: set[str] = set()
            for p in (spec or {}).get("memberOfTypes") or []:
                qp = _qualify(ns, p) if "::" not in p and _qualify(ns, p) in declared else p
                parents.add(qp)
            graph.setdefault(q, set()).update(parents)
    return {k: frozenset(v) for k, v in graph.items()}


def _qualify(ns: str, name: str) -> str:
    return f"{ns}::{name}" if ns else name


def ancestor_types(graph: dict[str, frozenset[str]], start: str) -> frozenset[str]:
    """The types reachable from ``start`` through ``memberOfTypes``: the types
    an entity of ``start`` may be ``in``, besides itself."""
    seen: set[str] = set()
    frontier = [start]
    while frontier:
        t = frontier.pop()
        for p in graph.get(t, frozenset()):
            if p not in seen:
                seen.add(p)
                frontier.append(p)
    return frozenset(seen)


def attribute_entity_type(
    schema: dict[str, Any], entity_type: str, attr: str
) -> str | None:
    """The entity type an attribute of ``entity_type`` holds (``Entity`` or a
    ``Set`` of one), or ``None`` when the schema types it otherwise or not at
    all."""
    for ns, body in schema.items():
        if not isinstance(body, dict):
            continue
        for t, spec in (body.get("entityTypes") or {}).items():
            if _qualify(ns, t) != entity_type:
                continue
            attrs = ((spec or {}).get("shape") or {}).get("attributes") or {}
            a = attrs.get(attr)
            if not isinstance(a, dict):
                return None
            if a.get("type") == "Set":
                a = a.get("element") or {}
            if a.get("type") == "Entity" and isinstance(a.get("name"), str):
                name = a["name"]
                return name if "::" in name or not ns else (
                    _qualify(ns, name) if _qualify(ns, name) in {
                        _qualify(ns, x) for x in body.get("entityTypes") or {}
                    } else name
                )
            return None
    return None


def check_hierarchy(
    policies_json: dict[str, Any], placement: EntityPlacement, schema: dict[str, Any]
) -> None:
    """Refuse every ``in`` the schema cannot make true.

    Walks the policy set in Cedar's own JSON form (``policies_to_json_str``),
    so this is the parser's reading of the text and not a regex over it. The
    subject of an ``in`` must be the ``principal`` or the ``resource``
    variable -- the two entities this release forms a hierarchy for -- and
    the object must be an entity literal, a set of them, or an attribute the
    schema types as an entity (or a set of one). The object's type must be
    the subject's own or reachable from it through ``memberOfTypes``;
    otherwise Cedar's validator types the test as ``false``, reports nothing,
    and the rule is inert. An ``in`` on the action is refused: action groups
    are a hierarchy this release does not form.
    """
    graph = member_of_graph(schema)

    def subject_type(node: Any, where: str) -> str:
        if isinstance(node, dict) and node.get("Var") in _SUBJECTS:
            return placement.subject_type(node["Var"])
        if isinstance(node, dict) and node.get("Var") == "action":
            raise HierarchyError(
                f"{where}: `action in …` is refused; action groups are a hierarchy "
                "this release does not form"
            )
        if isinstance(node, dict) and "." in node:
            raise HierarchyError(
                f"{where}: `in` over an attribute subject is refused; this release "
                "forms the hierarchy of the principal and the resource only"
            )
        raise HierarchyError(
            f"{where}: the subject of `in` must be `principal` or `resource`"
        )

    def object_types(node: Any, where: str) -> list[str]:
        if isinstance(node, dict) and "Value" in node:
            ent = (node["Value"] or {}).get(ENTITY_ESCAPE) if isinstance(node["Value"], dict) else None
            if isinstance(ent, dict) and isinstance(ent.get("type"), str):
                return [ent["type"]]
        if isinstance(node, dict) and "Set" in node:
            out: list[str] = []
            for element in node["Set"] or []:
                out.extend(object_types(element, where))
            return out
        if isinstance(node, dict) and "." in node:
            inner = node["."]
            left = inner.get("left") if isinstance(inner, dict) else None
            if isinstance(left, dict) and left.get("Var") in _SUBJECTS:
                t = attribute_entity_type(
                    schema, placement.subject_type(left["Var"]), inner.get("attr", "")
                )
                if t is not None:
                    return [t]
        raise HierarchyError(
            f"{where}: the object of `in` must be an entity literal, a set of "
            "them, or a principal/resource attribute the schema types as an entity"
        )

    def check(subject: str, objects: list[str], where: str) -> None:
        reachable = ancestor_types(graph, subject) | {subject}
        for obj in objects:
            if obj not in reachable:
                raise HierarchyError(
                    f"{where}: `in` tests a {subject} against {obj}::…, a relation "
                    f"{SCHEMA_FILE} does not declare (reachable from {subject}: "
                    f"{sorted(reachable - {subject}) or 'nothing'}). Cedar types the "
                    "test as false and reports nothing, so the rule would be silently "
                    "inert; declare the relation in memberOfTypes or drop the test"
                )

    def walk(node: Any, where: str) -> None:
        if isinstance(node, list):
            for n in node:
                walk(n, where)
            return
        if not isinstance(node, dict):
            return
        if "in" in node and isinstance(node["in"], dict) and "left" in node["in"]:
            spec = node["in"]
            check(subject_type(spec.get("left"), where), object_types(spec.get("right"), where), where)
        if "is" in node and isinstance(node["is"], dict) and "in" in node["is"]:
            spec = node["is"]
            check(subject_type(spec.get("left"), where), object_types(spec.get("in"), where), where)
        for v in node.values():
            walk(v, where)

    for pid, policy in (policies_json.get("staticPolicies") or {}).items():
        where = f"policy {pid}"
        for var in ("principal", "resource"):
            scope = policy.get(var) or {}
            if scope.get("op") == "in" and isinstance(scope.get("entity"), dict):
                check(placement.subject_type(var), [scope["entity"].get("type", "")], where)
            if scope.get("op") == "is" and isinstance(scope.get("in"), dict):
                ent = scope["in"].get("entity") if isinstance(scope["in"], dict) else None
                if isinstance(ent, dict):
                    check(placement.subject_type(var), [ent.get("type", "")], where)
        action = policy.get("action") or {}
        if action.get("op") == "in":
            entities = action.get("entities") or ([action["entity"]] if "entity" in action else [])
            if any(not str(e.get("type", "")).endswith("Action") for e in entities if isinstance(e, dict)):
                raise HierarchyError(
                    f"{where}: `action in …` names a non-action entity; action groups "
                    "are a hierarchy this release does not form"
                )
        walk(policy.get("conditions") or [], where)
