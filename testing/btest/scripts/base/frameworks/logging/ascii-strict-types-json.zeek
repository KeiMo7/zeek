# @TEST-DOC: LogAscii::strict_types in JSON mode writes unset fields as null and reports non-UTF-8 bytes while preserving them escaped.
#
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: btest-diff testing.log
# @TEST-EXEC: grep -o "log field.*escapes" stderr > utf8-warning
# @TEST-EXEC: btest-diff utf8-warning

@load tuning/json-logs

redef LogAscii::strict_types = T;

module Testing;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log &optional;
		msg: string &log &optional;
		n: count &log &optional;
	};
}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="testing"]);

	# Unset optional fields become explicit nulls.
	Log::write(LOG, [$msg="hello"]);

	# Invalid UTF-8 in a string: reported once, raw bytes preserved
	# as escapes, record not dropped.
	Log::write(LOG, [$ts=double_to_time(1234567890.0), $msg="bad \xc3\x28 bytes", $n=7]);
	Log::write(LOG, [$msg="more \xc3\x28 bytes"]);
	}
