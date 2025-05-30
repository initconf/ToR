module TOR;

hook tor_conn_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
{

        if ( rec$id$orig_h !in tor_table && rec$id$resp_h !in tor_table) {
                break;
        }
}

event zeek_init()
{
        local filter: Log::Filter = [
            $name="tor_conn",
            $path="tor_conn",
            $policy=tor_conn_policy];
        Log::add_filter(Conn::LOG, filter);
}
