package policybundle.examples.undefined_shapes

import rego.v1

# The operand every shape reads. format_int supports bases 2, 8, 10 and 16;
# any other base is *undefined* in OPA -- not an error -- which is the shape
# of evidence a parsing builtin cannot parse (json.unmarshal on non-JSON,
# base64url.decode on non-base64). The input supplies base 7.
formatted := format_int(input.n, input.base)

# ---- fail-open: undefined becomes a pass ----------------------------------

helper if {
	formatted == "5"
}

# A negated partial RULE: `not <undefined>` is true.
not_undefined_rule if {
	not helper
}

binds(n) if {
	format_int(n, input.base) == "5"
}

# A negated partial FUNCTION call: also true.
not_undefined_function if {
	not binds(input.n)
}

bad_legs := [n | some n in input.ns; format_int(n, input.base) != "ok"]

# A count over a comprehension: undefined legs are not collected, so a
# "no bad legs" check passes on an input where every leg was uncomputable.
count_comprehension_zero if {
	count(bad_legs) == 0
}

# ---- safe: undefined stays undefined -------------------------------------

positive if {
	formatted == "5"
}

every_undefined if {
	every n in input.ns {
		format_int(n, input.base) == "ok"
	}
}

max_undefined := max([n | some n in input.ns; format_int(n, input.base) != "zz"])

# A negated BUILTIN call: OPA hoists the call out of the negation, so the
# undefined is reached before `not` sees anything.
not_builtin_hoisted if {
	not format_int(input.n, input.base) == "5"
}

# ---- the shape the generated bundles rely on, on the side where it is right --

default allow := false

allow if {
	positive
}

failed_checks contains "the_check" if {
	not allow
	not helper
}
