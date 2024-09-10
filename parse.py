#!/usr/bin/env python3
import re

def parse_perf_data(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        stack=[]
        print("meta_info:")
        print("  trace_offcpu: false")
        print("  event_type: cpu-cycles")
        print("  android_sdk_version: 35")
        print("  android_build_type: userdebug")
        for line in lines:
            m = re.match(r'(.*) +([0-9]+) \[...\] +([0-9]+\.[0-9]+): +([0-9]+) (.*):', line)
            if m:
                print("sample:")
                event_count=int(m.group(4))
                print("  event_type: %s"%(m.group(5)))
                print("  time: %d"%(float(m.group(3))*1000000000))
                print("  event_count: %d"%(event_count))
                print("  thread_id: %s"%(m.group(2)))
                print("  thread_name: %s"%(m.group(1).rstrip()))
                continue
            if re.match(r'^$', line):
                first=True
                for s in stack:
                    m = re.match(r'\t +([0-9a-z]+) (.*) \((.*)\)', s)
                    if m:
                        addr=m.group(1)
                        symbol=m.group(2)
                        vaddr_file=m.group(3)
                        if first:
                            first=False
                            print("  vaddr_in_file: %s" % addr)
                            print("  file: %s" % vaddr_file)
                            print("  symbol: %s" % symbol)
                            print("  callchain:")
                        else:
                            print("    vaddr_in_file: %s" % addr)
                            print("    file: %s" % vaddr_file)
                            print("    symbol: %s" % symbol)
                stack=[]
                continue
            stack.append(line)
        file.close()

parse_perf_data('perf_data.txt')

