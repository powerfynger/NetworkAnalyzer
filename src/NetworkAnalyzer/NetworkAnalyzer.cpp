#include "NetworkAnalyzer.h"

void Flow::addPacketToFlow(int size)
{
    _byteCount += size;
    _packetCount += 1;
}

std::string Flow::getDstIP()
{
    return _dstIP;
}

std::string Flow::getSrcIP()
{
    return _srcIP;
}

const int Flow::getSrcPort()
{
    return _srcPort;
}

const int Flow::getDstPort()
{
    return _srcPort;
}

const int Flow::getPacketCount()
{
    return _packetCount;
}
const int Flow::getByteCount()
{
    return _byteCount;
}

bool Flow::operator==(Flow &other) const
{
    return (this->_dstIP == other.getDstIP() && this->_dstPort == other.getDstPort() && this->_srcIP == other.getSrcIP() && this->_srcPort == other.getSrcPort());
}

void FlowSaver::writeCSVHeader()
{
    if (!_csvFileDescr.is_open())
        _csvFileDescr.open(_fileName);
    _csvFileDescr << "Source IP,Source Port,Destination IP,Destination Port,Packet Count,Byte Count\n";
}

void FlowSaver::closeAllDescriptors()
{
    _csvFileDescr.close();
}

FlowSaver::~FlowSaver()
{
    _csvFileDescr.close();

}
void FlowSaver::writeFlowToCSV(Flow fl)
{
    // if (!_csvFile.is_open())
        // _csvFile.open(_fileName);
    _csvFileDescr << fl.getSrcIP() << "," << fl.getSrcPort() << "," << fl.getDstIP() << "," << fl.getDstPort() << "," << fl.getPacketCount() << "," << fl.getByteCount() << "\n";
}

void PacketAnalyzer::saveFlows()
{
    _flSaver.writeCSVHeader();
    for (auto flow : _flows)
    {
        _flSaver.writeFlowToCSV(flow);
    }
}

void PacketAnalyzer::analyzePacket(const u_char *packet, int packSize)
{
    struct ether_header *ethHeader = (struct ether_header *)packet;
    if (ntohs(ethHeader->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    struct ip *ipHeader = (struct ip *)(packet + ETHER_HDR_LEN);
    int ipHeaderLen = ipHeader->ip_hl << 2;

    if (ipHeader->ip_p != IPPROTO_TCP && ipHeader->ip_p != IPPROTO_UDP && ipHeader->ip_p != IPPROTO_IP)
    {
        return;
    }
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + ETHER_HDR_LEN + ipHeaderLen);

    int srcPort = ntohs(tcpHeader->source);
    int dstPort = ntohs(tcpHeader->dest);
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

    Flow tmp(srcIP, dstIP, srcPort, dstPort);
    for (auto &fl : _flows)
    {
        if (fl == tmp)
        {
            fl.addPacketToFlow(packSize);
            return;
        }
    }
    _flows.push_back(tmp);
}

void PacketAnalyzer::analyzePacketsFromFile(std::string fileName)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;

    handle = pcap_open_offline(fileName.c_str(), errbuf);
    if (handle == NULL)
    {
        std::cout << "Could not open " << fileName << " file\n";
        return;
    }

    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        analyzePacket(packet, header.len);
    }

    pcap_close(handle);
}
void PacketAnalyzer::analyzePacketsLive()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    char *dev;

    dev = pcap_lookupdev(errbuf);
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    while(true)
    {
        packet = pcap_next(handle, &header);
        analyzePacket(packet, header.len);
    }
}
