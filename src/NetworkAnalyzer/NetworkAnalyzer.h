#ifndef NETWORKANALYZER_H
#define NETWORKANALYZER_H

#include <iostream>
#include <vector>
#include <fstream>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

class Flow
{
public:
    Flow(std::string srcIP, std::string dstIP, int srcPort, int dstPort) : 
    _srcIP(srcIP), _dstIP(dstIP), _srcPort(srcPort), _dstPort(dstPort), _packetCount(1), _byteCount(0) {}
    
    void addPacketToFlow(int size);
    std::string getSrcIP();
    std::string getDstIP();
    const int getSrcPort();
    const int getDstPort();
    const int getPacketCount();
    const int getByteCount();

    bool operator==(Flow& other) const;

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
    FlowSaver(std::string fileName) : _fileName(fileName) {}
    void writeFlowToCSV(Flow fl);
    void writeCSVHeader();
private:
    std::ofstream _csvFile;
    std::string _fileName;
};

class PacketAnalyzer
{
public:
    PacketAnalyzer(FlowSaver flSaver) : _flSaver(flSaver) {}
    void analyzePacket(const u_char *packet, int packSize);
    void saveFlows();
private:
    FlowSaver& _flSaver;
    std::vector<Flow> _flows;
};

#endif