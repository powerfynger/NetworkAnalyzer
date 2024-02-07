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

int Flow::getSrcPort()
{
    return _srcPort;
}

int Flow::getDstPort()
{
    return _srcPort;
} 

int Flow::getPacketCount()
{
    return _packetCount;
}
int Flow::getByteCount()
{
    return _byteCount;
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
    _csvFile << 
    fl.getSrcIP() << "," << fl.getSrcPort() << "," <<
    fl.getDstIP() << "," << fl.getDstPort() << "," << 
    fl.getPacketCount() << "," << fl.getByteCount() << 
    "\n";
}

void PacketAnalyzer::saveFlows()
{
    _flSaver.writeCSVHeader();
    for (auto flow : _flows)
    {
        _flSaver.writeFlowToCSV(flow);
    }
}
