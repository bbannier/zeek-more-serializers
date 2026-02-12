# @TEST-DOC: Intended to be run explicitly, set `BENCHMARK_NUM` to the number of iterations to run
#
# @TEST-REQUIRES: test -n "$BENCHMARK_NUM"
# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	local b: bool = T;
	Zeek::more_serializers::detail::bench_storage(type_name(b), b);

	print "##########################################";

	local c: count = 1123123123;
	Zeek::more_serializers::detail::bench_storage(type_name(c), c);

	print "##########################################";

	local str: string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	Zeek::more_serializers::detail::bench_storage(type_name(str), str);

	print "##########################################";

	local v = vector(1, 2, 2, 3, 4, 5, 1, 12, 12, 12);
	Zeek::more_serializers::detail::bench_storage(type_name(v), v);

	print "##########################################";

	local s = set(1, 2, 2, 3, 4, 5, 1, 12, 12, 12);
	Zeek::more_serializers::detail::bench_storage(type_name(s), s);
	print "##########################################";

	local r = SumStats::SumStat($name="foo", $epoch=42sec, $reducers=set());
	Zeek::more_serializers::detail::bench_storage(type_name(r), r);
	print "##########################################";

	local x: count = 1123123123;
	Zeek::more_serializers::detail::bench_storage(type_name(x) ,x);
	print "##########################################";
	}

global ping_empty: event();
global ping_string: event(msg: string);
global ping_sumstat: event(msg: SumStats::SumStat);
global ping_set: event(msg: set[count]);
global ping_vector: event(msg: vector of count);

event zeek_init()
	{
	local evt: Cluster::Event;

	evt = Cluster::make_event(ping_empty);
	Zeek::more_serializers::detail::bench_event("ping_empty", "topic", evt);
	print "##########################################";

	evt = Cluster::make_event(ping_string, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	Zeek::more_serializers::detail::bench_event("ping_string", "topic", evt);
	print "##########################################";

	evt = Cluster::make_event(ping_sumstat, SumStats::SumStat($name="foo", $epoch=42sec, $reducers=set()));
	Zeek::more_serializers::detail::bench_event("ping_sumstat", "topic", evt);
	print "##########################################";

	evt = Cluster::make_event(ping_set, set(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
	Zeek::more_serializers::detail::bench_event("ping_set", "topic", evt);
	print "##########################################";

	evt = Cluster::make_event(ping_vector, vector(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
	Zeek::more_serializers::detail::bench_event("ping_vector", "topic", evt);
	print "##########################################";
	}
