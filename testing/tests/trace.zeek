# @TEST-DOC: Test Zeek parsing a trace file through the sess analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/sess.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init() &priority=5 {
    # the script of tpkt are not loaded even if the tpkt plugin is installed
    Analyzer::register_for_port(Analyzer::ANALYZER_TPKT, 102/tcp);
}

event sess::spdu(c: connection, is_orig: bool, si: int, payload_length: int) {
  print(fmt("Testing cotp: [orig_h=%s, orig_p=%s, resp_h=%s, resp_p=%s] %d | %d",
	    c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, si, payload_length));
}
