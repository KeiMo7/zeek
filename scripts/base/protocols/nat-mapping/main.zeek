module NATMapping;

@load ./spicy-events

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register NAT-PMP and PCP for.
	const ports = {5351/tcp} &redef;

	## Record type containing the column fields of the Redis log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## Address of host that requested the mapping.
		int_addr: addr &log;
		## Internal port for the mapping.
		int_port: port &log;
		## External port for the mapping.
		ext_port: port &log;
		## The requested lifetime for the mapping.
		lifetime: interval &log;
		## Result of the mapping request.
		result: ResultCode &log &optional;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Timeout to log requests without a response.
	const request_timeout = 30sec &redef;
}

function request_expire_callback(t: table[PortData, addr] of connection, idx: any) : interval {
	local port_data: PortData;
	local int_addr: addr;

	[port_data, int_addr] = idx;
	local c: connection = t[port_data, int_addr];

	# request timed out, log it as such.
	Log::write(NATMapping::LOG, Info(
		$ts = network_time(),
		$uid = c$uid,
		$id = c$id,
		$int_addr = int_addr,
		$int_port = port_data$int_port,
		$ext_port = port_data$ext_port,
		$lifetime = port_data$lifetime,
		$result = TIMEOUT));
}

global active_requests: table[PortData, addr] of connection &create_expire=request_timeout &expire_func=request_expire_callback;

event zeek_init() &priority=5
	{
	Log::create_stream(NATMapping::LOG, Log::Stream($columns=Info, $path="nat-mapping",
	    $policy=log_policy));

	Analyzer::register_for_ports(Analyzer::ANALYZER_NATMAPPING, ports);
	}

event natpmp_request(c: connection, data: PortData)
	{
	if ( [data, c$id$orig_h] in active_requests ) {
		delete active_requests[data, c$id$orig_h];

		# request timed out, log it as such.
		Log::write(NATMapping::LOG, Info(
			$ts = network_time(),
			$uid = c$uid,
			$int_addr = c$id$orig_h,
			$int_port = data$int_port,
			$ext_port = data$ext_port,
			$lifetime = data$lifetime,
			$result = TIMEOUT));
	}

	active_requests[data, c$id$orig_h] = c;
	}

event natpmp_response(c: connection, data: PortData, result: ResultCode)
	{
	if ( [data, c$id$orig_h] in active_requests )
		delete active_requests[data, c$id$orig_h];

	Log::write(NATMapping::LOG, Info(
		$ts = network_time(),
		$uid = c$uid,
		$id = c$id,
		$int_addr = c$id$orig_h,
		$int_port = data$int_port,
		$ext_port = data$ext_port,
		$lifetime = data$lifetime,
		$result = result));
	}
