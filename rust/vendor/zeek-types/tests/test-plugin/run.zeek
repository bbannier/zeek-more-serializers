# FIXME(bbannier): We should generate the declaration automatically, e.g., from a proc macro.
module GLOBAL;
global sum: function(a: count, b: count): count;

event zeek_init()
	{
	local s = sum(1, 2);
	assert s == 3, fmt("s=%s", s);
	}
