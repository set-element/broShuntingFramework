# impelementation of queue handler for the shunt policy
#
# [bro][shunt policy][queue mngr] -> application.py -> router
#                                 -> query.py -> router for acl list
#
# connection drops are done independant  of the ip <-> ip pair blocks so that 
#  the main blocks can be added or removed without changing any of the microstate
#
# when shunting [ip,ip] pairs, set the orig_p and resp_p to zero to identify pair 
#	shunting vs. connection shunting.
#
@load base/protocols/conn
@load base/utils/paths
@load base/utils/numbers
@load base/utils/addrs

module Shunt;

export {
	redef enum Notice::Type += {
		ShuntQueueAdd,
		ShuntQueueMalformed,
		ShuntQueueReplace,
		};

	type shunt_entity: record {
		ent_type: string &default="NULL"; # CONN, IP_PAIR etc...
		ent_count: count &default=0;	  # how many times the cid has been flagged
		ent_time: double &default=0.0;	  # timestamp for latest invocation
		};

	# library of currently shunted connections
	global shunted_connections: table[conn_id] of shunt_entity;
	# queue of waiting shunts
	global shunt_queue: set[shunt_entity];

	global shunt_connection: function(c: connection, enttype: string, dtime: double) : count;
	global shunt_list: function() : count;

	## --- configuration data --- ##
	const batch_inserts = T &redef;
	const batch_interval = 10 sec &redef;
	const queue_min = 1 &redef;
	const queue_max = 1000 &redef;

	# time period (in sec) after which a entry is no longer
	#  consitered valid
	const stale_shunt_entry = 3600*24; # one day ...

	}

### ----- Local Constants ----- ###
const SEP = "\n";
const ACL = "ip access-list extended shunt_list";
const DMPACL = " show ip access-list shunt_list";
const PTH = "deny tcp host ";
const EQ = " eq ";
const HST = " host ";
const EST = " established ";
const NO = " no ";

### ----- Functions ----- ###

function shunt_connection(c: connection, enttype: string, dtime: double) : count
	{
	# ret vals: 0: conn shunted, 1: shunt ignored, 2: malformed value
	local ret_val: count = 0;
	local t_se: shunt_entity;

	# hate to be cynical, but lets check a few things ...
	#if ( ! c?$shunt_element ) {
	#	ret_val = 2;
	#	return ret_val;
	#	}

	if ( dtime == 0.0 )
		dtime = time_to_double( network_time() );


	# look for moving backwareds in time as well
	#if ( time_to_double(network_time() )

	if ( c$id in shunted_connections ) {

		t_se = shunted_connections[c$id];

		# if the record is too stale, replace it with the new value
		if ( dtime - t_se$ent_time > stale_shunt_entry ) {

			# log this and replace the current table value
			t_se$ent_type = enttype;
			t_se$ent_count = 1;
			t_se$ent_time = dtime; 

			}
		
		} # end prev processed c$id
	else {
		# new value - set data values
		t_se$ent_type = enttype;
		t_se$ent_count = 1;
		t_se$ent_time = dtime; 

		add shunt_queue[t_se];
		}


	return ret_val;
	}


### ----- Events ----- ###
event batch_run()
	{
	local qlen = |shunt_queue|;
	local block_string: string;

	if ( qlen >= queue_min ) {

		local s_acl: string;
		local t_shunt_entity: shunt_entity;

		#print fmt("----- start queue dump -----");
		# run through the queue list and build the appropriate string
		for ( q in shunt_queue ) {
			#print q;
			#t_shunt_entity = shunted_connections[q];
	
			#shunt_st = fmt("%s %s %s %s %s %s %s %s %s", PTH, q$orig_h, EQ,q$orig_p, HST, q$resp_h, EST, EQ, q$resp_p);
			#print shunt_st;
			}
		#print fmt("----- end queue dump -----");
		}

	#print "in batch run ...";
	schedule batch_interval { batch_run() };
	}



event bro_init() &priority=5
        {

	if ( Shunt::batch_inserts )
		schedule Shunt::batch_interval { batch_run() };
        }


