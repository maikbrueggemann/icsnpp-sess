module sess;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:           time    &log;
        uid:          string  &log;
        id:           conn_id &log;
        bytes_orig:   count   &log &default=0;
        bytes_resp:   count   &log &default=0;
        packets_orig: count   &log &default=0;
        packets_resp: count   &log &default=0;
    };

    redef record connection += {
        sess_info: Info &optional;
    };

    global log_sess: event(rec: Info);
}

function get_info(c: connection): Info {
    if(!c?$sess_info) {
        c$sess_info = [
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
        ];
    }
    return c$sess_info;
}

event zeek_init() &priority=5 {
    Log::create_stream(sess::LOG, [$columns = Info, $ev = log_sess, $path="sess"]);
}

event spdu(c: connection, is_orig: bool, si: int, payload: string) {

    local info = get_info(c);

    if(is_orig) {
        info$bytes_orig += |payload|;
        info$packets_orig += 1;
    } else {
        info$bytes_resp += |payload|;
        info$packets_resp += 1;
    }
}

event connection_state_remove(c: connection) {
    if ( c?$sess_info ) {
        Log::write(LOG, c$sess_info);
        delete c$sess_info;
    }
}
