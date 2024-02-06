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


void PacketAnalyzer::saveFlows()
{
    for (auto fl : _flows)
    {
        _flSaver.writeFlowToCSV(fl);
    }
}
