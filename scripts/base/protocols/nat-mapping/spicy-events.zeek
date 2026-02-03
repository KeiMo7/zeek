module NATMapping;

export {
	type PortData: record {
		# Internal port
		int_port: port;
		# External port
		ext_port: port;
		# Lifetime
		lifetime: interval;
	};

	type PCPData: record {
		# Ports and interval
		ports: PortData;
		# Internal IP
		internal_ip: addr;
		# High bits of nonce
		nonce_high: count;
		# Low bits of nonce
		nonce_low: count;
	};

	type ResultCode: enum {
		SUCCESS = 0,
		PROTOCOL_ERROR = 1,
		POLICY_FAILURE = 2,
		TIMEOUT = 3,
	};
}

## Generated for NATPMP mapping requests.
global natpmp_request: event(c: connection, data: PortData);

## Generated for NATPMP mapping requests.
global natpmp_response: event(c: connection, data: PortData, result: ResultCode);

## Generated for NAT mapping requests.
##
## c: The connection.
##
## data: A record for the mapping.
global pcp_map_request: event(c: connection, data: PCPData);

## Generated for NAT mapping responses.
##
## c: The connection.
##
## data: A record for the mapping.
##
## result: The result of the mapping request.
global pcp_map_response: event(c: connection, data: PCPData, result: ResultCode);
