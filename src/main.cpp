#include "NetworkAnalyzer/NetworkAnalyzer.h"

int main()
{
    FlowSaver flSaver("test.csv");
    PacketAnalyzer pckAnalyzer(flSaver);
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    char *dev;

    dev = pcap_lookupdev(errbuf);
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    for (int i = 0; i < 10; i++)
    {
        packet = pcap_next(handle, &header);
        pckAnalyzer.analyzePacket(packet, header.len);

    }
    pckAnalyzer.saveFlows();

    return 0;
}