# @TEST-EXEC: zeek -NN Zeek::more_serializers |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
