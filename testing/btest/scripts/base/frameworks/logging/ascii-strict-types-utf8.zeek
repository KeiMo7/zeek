# @TEST-DOC: LogAscii::strict_types reports non-UTF-8 bytes in TSV output while keeping the line structure intact.
#
# @TEST-EXEC: zeek -b %INPUT 2>stderr
# @TEST-EXEC: test `grep -vc "^#" testing.log` -eq 2
# @TEST-EXEC: test `grep -c "not valid UTF-8" stderr` -eq 1
# @TEST-EXEC: btest-diff-cut -m testing.log

redef LogAscii::strict_types = T;

module Testing;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		msg: string &log;
		n: count &log &optional;
	};
}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="testing"]);

	# Separators, newlines, control characters and invalid UTF-8 must
	# all be escaped so the record stays on a single line.
	Log::write(LOG, [$msg="tab\tand\nnewline\x01and\xc3\x28bad", $n=3]);
	Log::write(LOG, [$msg="plain"]);
	}
