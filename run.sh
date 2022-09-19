cargo build
sudo setcap cap_net_raw,cap_net_admin=eip /home/andrea/pds_project/packet_sniffer/target/debug/packet_sniffer
/home/andrea/pds_project/packet_sniffer/target/debug/packet_sniffer