# @TEST-DOC: LogAscii::strict_types warns when a previous run left a log file with different column types at the same path.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: zeek -b %INPUT Testing::version=2 2>stderr
# @TEST-EXEC: grep -o "log file.*overwriting it" stderr | sed "s/\t/ /g" > mismatch
# @TEST-EXEC: btest-diff mismatch
# @TEST-EXEC: btest-diff-cut -m strict.log

redef LogAscii::strict_types = T;

module Testing;

export {
	redef enum Log::ID += { LOG };

	const version = 1 &redef;
}

type Info1: record {
	ts: time &log;
	n: count &log;
};

type Info2: record {
	ts: time &log;
	n: int &log;
};

event zeek_init()
	{
	if ( version == 1 )
		{
		Log::create_stream(LOG, [$columns=Info1, $path="strict"]);
		Log::write(LOG, [$ts=double_to_time(1234567890.0), $n=42]);
		}
	else
		{
		Log::create_stream(LOG, [$columns=Info2, $path="strict"]);
		Log::write(LOG, [$ts=double_to_time(1234567890.0), $n=-3]);
		}
	}
