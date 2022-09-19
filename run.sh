cargo build
sudo setcap cap_net_raw,cap_net_admin=eip $(pwd)/target/debug/packet_sniffer
$(pwd)/target/debug/packet_sniffer