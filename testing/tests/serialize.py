# @TEST-EXEC: python3 %INPUT > generated.zeek
# @TEST-EXEC: zeek generated.zeek >output 2>&1
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE generator.py
from string import Template
from textwrap import dedent


def gen(format: str) -> None:
    SKELETON = Template(
        dedent("""
        type Record: record {
            a: count;
            b: any &optional;
        };

        event zeek_init() {
        $body
        }
    """)
    )

    TEST = Template(
        dedent("""
        {
            local val$idx: $ty = $val;

            # Check that serialization roundtrips.
            local serialized$idx = Zeek::more_serializers::serialize_val(val$idx, Zeek::more_serializers::$format);
            local deserialized$idx = Zeek::more_serializers::deserialize_val(serialized$idx, $ty, Zeek::more_serializers::$format) as $ty;

            # Dump serialized format for baselining.
            print type_name(val$idx), val$idx, serialized$idx, deserialized$idx;
        }
        """)
    )

    body = ""
    for idx, (ty, val) in enumerate(
        [
            # None tested via `&optional` record fields.
            # Bool.
            ("bool", "T"),
            ("bool", "F"),
            # Count.
            ("count", 0),
            ("count", 9),
            # Int.
            ("int", 0),
            ("int", 9),
            ("int", -9),
            # Double.
            ("double", 0),
            ("double", 0.5),
            ("double", 1e10),
            ("double", -1e10),
            # Enum.
            ("Notice::Type", "Notice::Tally"),
            # String.
            ("string", '""'),
            ("string", '"abc"'),
            ("string", '"abc🚜"'),
            # Port.
            ("port", "8080/tcp"),
            ("port", "8080/udp"),
            ("port", "1/icmp"),
            ("port", "2/unknown"),
            # Addr.
            ("addr", "1.2.3.4"),
            ("addr", "[::1]"),
            # Subnet.
            ("subnet", "1.2.3.4/32"),
            ("subnet", "[::]/64"),
            ("subnet", "0.0.0.0/1"),
            ("subnet", "128.0.0.0/1"),
            ("subnet", "[::ffff:0.0.0.0]/1"),
            # Interval.
            ("interval", "1sec"),
            ("interval", "1min"),
            ("interval", "-1day"),
            # Time.
            ("time", "double_to_time(0)"),
            ("time", "double_to_time(0) - 365day"),
            ("time", "double_to_time(0) + 365day"),
            # Vector.
            ("vector of count", "vector()"),
            ("vector of count", "vector(1, 2, 3, )"),
            # List tested via tables.
            # Table.
            ("table[string] of count", "{}"),
            ("table[string] of count", '{["a"]=1, ["b"]=2}'),
            ("set[string]", "{}"),
            ("set[string]", '{"a", "b", "c"}'),
            # Pattern.
            ("pattern", "/.*/"),
            # Record.
            ("Record", "Record($a=1, $b=2)"),
            ("Record", "Record($a=1)"),
            # ("Record", "Record($a=1, $b=vector())"), # FIXME(bbannier): broken due to https://github.com/zeek/zeek/issues/5114.
            # ("Record", "Record($a=1, $b=vector(1, 2, 3))"),
        ]
    ):
        body += TEST.substitute({"idx": idx, "val": val, "ty": ty, "format": format})

    script = SKELETON.substitute(body=body)

    print(script)


# @TEST-END-FILE

from generator import gen  # noqa: F811, E402

gen("FormatBinary")

# @TEST-START-NEXT
from generator import gen  # noqa: F811, E402

gen("FormatHuman")
