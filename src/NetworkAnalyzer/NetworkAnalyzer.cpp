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

bool Flow::operator==(Flow& other) const
{
    return (this->_dstIP == other.getDstIP() && this->_dstPort == other.getDstPort() && this->_srcIP == other.getSrcIP() && this->_srcPort == other.getSrcPort());
}

void FlowSaver::writeCSVHeader()
{
    if (!_csvFile.is_open())
        _csvFile.open(_fileName);
    _csvFile << "Source IP,Source Port,Destination IP,Destination Port,Packet Count,Byte Count\n";
}

void FlowSaver::writeFlowToCSV(Flow fl)
{
    if (!_csvFile.is_open())
        _csvFile.open(_fileName);
    _csvFile << fl.getSrcIP() << "," << fl.getSrcPort() << "," << fl.getDstIP() << "," << fl.getDstPort() << "," << fl.getPacketCount() << "," << fl.getByteCount() << "\n";
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