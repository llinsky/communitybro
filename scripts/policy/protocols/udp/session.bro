##! This script handles UDP session settings

module udp;

export {
    ## Remove connections upon Bro emitting an appropriate end message.
    ## Additionally, it can be leveraged instead of the explicit UDP timeout
    ## values in appropriate scripts.
	const connection_remove_on_end = T &redef;
}
