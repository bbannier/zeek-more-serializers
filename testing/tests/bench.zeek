# @TEST-DOC: Intended to be run explicitly, set `BENCHMARK_NUM` to the number of iterations to run
#
# @TEST-REQUIRES: test -n "$BENCHMARK_NUM"
# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	local b: bool = T;
	print type_name(b);
	Zeek::more_serializers::detail::bench_storage(b);

	print "##########################################";

	local c: count = 1123123123;
	print type_name(c);
	Zeek::more_serializers::detail::bench_storage(c);

	print "##########################################";

	local str: string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	print type_name(str);
	Zeek::more_serializers::detail::bench_storage(str);

	print "##########################################";

	local v = vector(1, 2, 2, 3, 4, 5, 1, 12, 12, 12);
	print type_name(v);
	Zeek::more_serializers::detail::bench_storage(v);

	print "##########################################";

	local s = set(1, 2, 2, 3, 4, 5, 1, 12, 12, 12);
	print type_name(s);
	Zeek::more_serializers::detail::bench_storage(s);
	print "##########################################";

	local r = SumStats::SumStat($name="foo", $epoch=42sec, $reducers=set());
	print type_name(r);
	Zeek::more_serializers::detail::bench_storage(r);
	print "##########################################";

	local x: count = 1123123123;
	print type_name(x);
	Zeek::more_serializers::detail::bench_storage(x);
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
	print "ping_empty";
	Zeek::more_serializers::detail::bench_event("topic", evt);
	print "##########################################";

	evt = Cluster::make_event(ping_string, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	print "ping_string";
	Zeek::more_serializers::detail::bench_event("topic", evt);
	print "##########################################";

	evt = Cluster::make_event(ping_sumstat, SumStats::SumStat($name="foo", $epoch=42sec, $reducers=set()));
	print "ping_sumstat";
	Zeek::more_serializers::detail::bench_event("topic", evt);
	print "##########################################";

	evt = Cluster::make_event(ping_set, set(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
	print "ping_set";
	Zeek::more_serializers::detail::bench_event("topic", evt);
	print "##########################################";

	evt = Cluster::make_event(ping_vector, vector(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
	print "ping_vector";
	Zeek::more_serializers::detail::bench_event("topic", evt);
	print "##########################################";
	}
