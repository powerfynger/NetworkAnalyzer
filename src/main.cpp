#include <unistd.h>
#include "NetworkAnalyzer/NetworkAnalyzer.h"

int main(int argc, char *argv[])
{
    int opt;
    std::string _inputFileName;;
    std::string _saverFileName = "test.csv";

    while ((opt = getopt(argc, argv, "o:r:")) != -1)
    {
        switch (opt)
        {
        case 'o':
            _saverFileName = optarg;
            break;
        case 'r':
            _inputFileName = optarg;
            break;
        default:
            std::cerr << "Usage: " << argv[0] << " -o <output file name .csv> -r <input file name .pcap>\n";
            return 1;
        }
    }

    FlowSaver flSaver(_saverFileName);
    PacketAnalyzer pckgAnalyzer(flSaver);
    if (_inputFileName.length() == 0) pckgAnalyzer.analyzePacketsLive();
    else pckgAnalyzer.analyzePacketsFromFile(_inputFileName);
    pckgAnalyzer.saveFlows();
    return 0;
}