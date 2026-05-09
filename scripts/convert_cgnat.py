import re
import csv
import sys

def ip_section(lines, nat_ip):
    rows = []
    for line in lines:
        line = line.strip()
        if not line or "Inside User" in line:
            continue

        parts = re.split(r"\s+", line)
        if len(parts) < 4:
            continue

        inside_ip = parts[0]
        start = parts[1]
        end = parts[3]

        rows.append([nat_ip, inside_ip, start, end])

    return rows


def convert(input_file, output_file):
    with open(input_file, "r") as f:
        lines = f.readlines()

    current_nat = None
    buffer = []
    all_rows = []

    for line in lines:
        line = line.strip()

        if line.startswith("NAT Address:"):
            if current_nat and buffer:
                all_rows.extend(ip_section(buffer, current_nat))
                buffer = []

            current_nat = line.split(":")[1].strip()

        elif line.startswith("Inside User"):
            continue

        else:
            buffer.append(line)

    if current_nat and buffer:
        all_rows.extend(ip_section(buffer, current_nat))

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["nat", "inside", "start_port", "end_port"])
        writer.writerows(all_rows)

    print(f"Converted {len(all_rows)} entries -> {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 convert_cgnat.py input.txt output.csv")
        sys.exit(1)

    convert(sys.argv[1], sys.argv[2])