module TOR;

export {
	redef enum Notice::Type += { incoming, outgoing, };

	type tor_Idx: record {
		torip: addr;
	};

	type tor_Val: record {
		torip: addr;
	};

	global tor_feed = fmt("%s/feeds/TOR.24hrs", @DIR) &redef;
	global tor_table: table[addr] of tor_Val = table() &redef;
}

event Input::end_of_data(name: string, source: string)
	{
	if ( /TOR.24hrs/ in name && source == "tor_feed" )
		{
		print fmt("end_of_data: name is %s source is %s", name, source);
		}
	}

# incase you want to do something with IPs
# tap into events of input-framework
event line(description: Input::TableDescription, tpe: Input::Event,
    left: tor_Idx, right: tor_Val)
	{
	local torip = right$torip;

	if ( tpe == Input::EVENT_NEW )
		{
		#print fmt ("NEW IP");
		}
	if ( tpe == Input::EVENT_CHANGED )
		{
		#print fmt ("Changed IP");
		}
	if ( tpe == Input::EVENT_REMOVED )
		{
		#print fmt ("Removed IP %s", right$torip );
		}
	}

event zeek_init() &priority=10
	{
	Input::add_table([ $source=tor_feed, $name="tor_table", $idx=tor_Idx,
	    $val=tor_Val, $destination=tor_table, $mode=Input::REREAD, $ev=line ]);
	}

event connection_established(c: connection)
	{
	local src = c$id$orig_h;
	local dst = c$id$resp_h;
	local source_tor: bool = F;

	if ( src !in tor_table && dst !in tor_table )
		return;

	source_tor = src in TOR::tor_table ? T : F;

	if ( source_tor )
		NOTICE([ $note=incoming, $conn=c, $msg=fmt("Connection Established") ]);
	else
		NOTICE([ $note=outgoing, $conn=c, $msg=fmt("Connection Established") ]);
	}
	# if you want to do other things with TOR traffic
	# best to tap into this event

	#event connection_state_remove(c: connection)
	#{
	#	local src = c$id$orig_h ;
	#	local dst = c$id$resp_h;
	#	local source_tor: bool = F;
	#
	#	if (src !in tor_table && dst !in tor_table)
	#		return;
	#	source_tor = src in TOR::tor_table ? T : F;
	#
	#	if (source_tor)
	#		print "Tor: incoming";
	#	else
	#		print "Tor: incoming";
	#}
