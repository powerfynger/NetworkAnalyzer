#include <unistd.h>
#include <cstdlib>
#include "NetworkAnalyzer/NetworkAnalyzer.h"

int main(int argc, char *argv[])
{
    int opt;
    std::string _inputFileName;;
    std::string _saverFileName = "test.csv";
    int numberPacketsToScan;

    while ((opt = getopt(argc, argv, "o:r:p:")) != -1)
    {
        switch (opt)
        {
        case 'o':
            _saverFileName = optarg;
            break;
        case 'r':
            _inputFileName = optarg;
            break;
        case 'p':
            numberPacketsToScan = std::atoi(optarg);
            break;
        default:
            std::cerr << "Usage: " << argv[0] << " -o <output file name .csv> -r <input file name .pcap> -p <number of packets to capture or -1 for infinite scan\n";
            return 1;
        }
    }

    FlowSaver flSaver(_saverFileName);
    PacketAnalyzer pckgAnalyzer(flSaver);
    if (_inputFileName.length() == 0) pckgAnalyzer.analyzePacketsLive(numberPacketsToScan);
    else pckgAnalyzer.analyzePacketsFromFile(_inputFileName);
    pckgAnalyzer.saveFlows();
    flSaver.closeAllDescriptors();

    std::string com("python3 main_analyzer.py ");
    com += _saverFileName;
    std::system(com.c_str());
    return 0;
}