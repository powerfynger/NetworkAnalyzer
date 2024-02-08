import csv, sys
from collections import defaultdict

def analyze_flows(file_name):
    stats = defaultdict(lambda: [0, 0, 0, 0])
    with open(file_name, 'r') as csv_file:
        reader = csv.reader(csv_file,delimiter=',')
        header = next(reader)

        for row in reader:
            # First number pair recv, second sent
            source_ip, _, dest_ip, _, packet_count, byte_count = row
            stats[source_ip][2] += int(packet_count)
            stats[source_ip][3] += int(byte_count)
            stats[dest_ip][0] += int(packet_count)
            stats[dest_ip][1] += int(byte_count)
    return stats

def write_flows_to_csv(data, file_name):

    with open(file_name, "w") as csv_file:
        header = ["IP address", "Packets recieved", "Bytes recieved", "Packets sent", "Bytes sent"];
        writer = csv.writer(csv_file)
        writer.writerow(header)
        for ip in data:
            writer.writerow([ip, data[ip][0], data[ip][1], data[ip][2], data[ip][3]])



def main():
    input_filename = sys.argv[1]
    output_filename = input_filename + '_output.csv'
    data = analyze_flows(input_filename)
    write_flows_to_csv(data, output_filename)


if __name__ == "__main__":
    main()