#ifndef NETWORKANALYZER_H
#define NETWORKANALYZER_H

#include <iostream>
#include <vector>


class Flow
{
public:
    Flow(std::string srcIP, std::string dstIP, int srcPort, int dstPort) : 
    _srcIP(srcIP), _dstIP(dstIP), _srcPort(srcPort), _dstPort(dstPort), _packetCount(1), _byteCount(0) {}
    
    void addPacketToFlow(int size);
    std::string getSrcIP();
    std::string getDstIP();
    int getSrcPort();
    int getDstPort();

private:
    std::string _srcIP;
    std::string _dstIP;
    int _srcPort;
    int _dstPort;
    int _packetCount;
    int _byteCount;
};

class FlowSaver
{
public:
    void writeFlowToCSV(Flow fl);
private:

};

class PacketAnalyzer
{
public:
    void analyzePacket();
    void saveFlows();
private:
    FlowSaver _flSaver;
    std::vector<Flow> _flows;
};

#endif