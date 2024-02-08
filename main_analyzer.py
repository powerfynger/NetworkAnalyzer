import csv
from collections import defaultdict

def analyze_flows(file_name):
    stats = defaultdict(lambda: [0, 0, 0, 0])

    with open(file_name, 'r') as csv_file:
        reader = csv.reader(csv_file,delimiter=',')
        header = next(reader)

        for row in reader:
            source_ip, _, dest_ip, _, packet_count, byte_count = row
            print(source_ip)
            stats[source_ip][2] += int(packet_count)
            stats[source_ip][3] += int(byte_count)
            stats[dest_ip][0] += int(packet_count)
            stats[dest_ip][1] += int(byte_count)
    # print(stats.)
    return stats

def main():
    # input_filename = sys.argv[1]
    input_filename = 'network_data.csv'
    output_filename = input_filename + '_output.csv'
    analyze_flows(input_filename)
    # df = pd.read_csv(input_filename)
    # print(df)

if __name__ == "__main__":
    main()