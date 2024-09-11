#!/usr/bin/env python3
import re

filter_tid = ''
# filter_tid = '3559'
with open('sample.txt', 'r') as file:
    lines = file.readlines()
    file.close()
    tid=""
    process_name=""
    event_count=0
    time=0.0
    symbol=""
    vaddr_in_file=""
    file=""
    items=[]
    in_callchain = False
    callchain = []
    tids_to_items = {}
    converted_traces = []

    for line_idx in range(len(lines)):
        line = lines[line_idx]
        if line.strip() == "sample:":
            if tid and (filter_tid == '' or tid == filter_tid):
                items.append({
                    'type': event_type,
                    'process_name': process_name,
                    'tid': tid,
                    'time': time,
                    'symbol': symbol,
                    'event_count': event_count,
                    'callchain': callchain,
                    'vaddr_in_file': vaddr_in_file,
                    'file': file
                })
            tid = ""
            process_name = ""
            event_count = 0
            time = 0.0
            symbol = ""
            callchain = []
            in_callchain = False
        if not in_callchain:
            if line.strip().startswith("event_type:"):
                event_type = line.split(":")[1].strip()
            elif line.strip().startswith("thread_id:"):
                tid = line.split(":")[1].strip()
            elif line.strip().startswith("thread_name:"):
                process_name = line.split(":")[1].strip()
            elif line.strip().startswith("time:"):
                time = float(line.split(":")[1].strip()) / 1e9  # Convert nanoseconds to seconds
            elif line.strip().startswith("event_count:"):
                event_count = int(line.split(":")[1].strip())
            elif line.strip().startswith("symbol:"):
                symbol = line.split(":")[1].strip()
                if symbol == '[unknown]':
                    symbol = "%s:0x%s"%(file, vaddr_in_file)
                else:
                    symbol = "%s:%s"%(file, symbol)
            elif line.strip().startswith("vaddr_in_file:"):
                vaddr_in_file = line.split(":")[1].strip()
            elif line.strip().startswith("file:"):
                file = line.split(":")[1].strip()
            elif line.strip() == "callchain:":
                in_callchain = True
                callchain.append({
                    'symbol': symbol,
                    'file': file,
                    'vaddr_in_file': vaddr_in_file,
                    'merge_next': False,
                    'merge_prev': False
                })
        elif in_callchain and line.strip().startswith("symbol:"):
            symbol_ = line.split(":")[1].strip()
            file_ = lines[line_idx - 1].split(":")[1].strip()
            vaddr_in_file_ = lines[line_idx - 2].split(":")[1].strip()
            if symbol_== '[unknown]':
                symbol_= "%s:0x%s"%(file_, vaddr_in_file_)
            else:
                symbol_ = "%s:%s"%(file_, symbol_)
            callchain.append({
                'symbol': symbol_,
                'file': file_,
                'vaddr_in_file': vaddr_in_file_,
                'merge_next': False,
                'merge_prev': False
            })
        
    # Add the last sample
    if tid and (filter_tid == '' or tid == filter_tid):
        items.append({
            'type': event_type,
            'process_name': process_name,
            'tid': tid,
            'time': time,
            'symbol': symbol,
            'event_count': event_count,
            'callchain': callchain,
            'vaddr_in_file': vaddr_in_file,
            'file': file,
        })

    # reverse the challcain
    for item in items:
        item['callchain'].reverse()

    # Print the first sample
    # if items:
    #     first_sample = items[0]
    #     print("First sample:")
    #     print(f"  Type: {first_sample['type']}")
    #     print(f"  Process Name: {first_sample['process_name']}")
    #     print(f"  Thread ID: {first_sample['tid']}")
    #     print(f"  Time: {first_sample['time']:.6f}")
    #     print(f"  Symbol: {first_sample['symbol']}")
    #     print(f"  Event Count: {first_sample['event_count']}")
    #     print(f"  Vaddr In File: {first_sample['vaddr_in_file']}")
    #     print(f"  File: {first_sample['file']}")
    #     print("  Callchain:")
    #     for call in first_sample['callchain']:
    #         print(f"    {call}")
    # else:
    #     print("No samples found.")

    for item in items:
        if item['tid'] not in tids_to_items:
            tids_to_items[item['tid']] = []
        tids_to_items[item['tid']].append(item)
    for tid in tids_to_items:
        items = tids_to_items[tid]
        for idx in range(1, len(items)):
            # check every stack in items[idx] and items[idx-1]
            for i in range(len(items[idx]['callchain'])):
                if i < len(items[idx-1]['callchain']):
                    if items[idx]['callchain'][i]['symbol'] == items[idx-1]['callchain'][i]['symbol'] \
                        and items[idx]['callchain'][i]['file'] == items[idx-1]['callchain'][i]['file'] \
                        and items[idx]['callchain'][i]['vaddr_in_file'] == items[idx-1]['callchain'][i]['vaddr_in_file']:
                        items[idx-1]['callchain'][i]['merge_next'] = True
                        items[idx]['callchain'][i]['merge_prev'] = True
                    else: # below path will not merge
                        break
    
    # here convert to systrace format
    for tid in tids_to_items:
        items = tids_to_items[tid]
        for idx in range(len(items)):
            item = items[idx]
            trace_line = "%16s-%-7s (%7s) [000] .....    %.6f: tracing_mark_write: C|%s|%s|%d" % (
                item['process_name'],
                item['tid'],
                item['tid'],
                item['time'],
                item['tid'],
                "perfsample_count",
                item['event_count'])
            converted_traces.append({"time": item['time'], "trace_line": trace_line})
            for i in range(len(item['callchain'])):
                if not item['callchain'][i]['merge_prev']:
                    trace_line = "%16s-%-7s (%7s) [000] .....    %.6f: tracing_mark_write: B|%s|%s" % (
                        item['process_name'],
                        item['tid'],
                        item['tid'],
                        item['time'],
                        item['tid'],
                        item['callchain'][i]['symbol']
                    )
                    converted_traces.append({"time": item['time'], "trace_line": trace_line})
                    # print(trace_line)
            for j in range(len(item['callchain'])):
                i = len(item['callchain']) - j - 1
                if not item['callchain'][i]['merge_next']:
                    t = item['time']
                    if idx < len(items) - 1:
                        t = items[idx+1]['time']
                    else:
                        t = item['time'] + int(item['event_count'])/5/1000000000
                    trace_line = "%16s-%-7s (%7s) [000] .....    %.6f: tracing_mark_write: E|%s|%s" % (
                        item['process_name'],
                        item['tid'],
                        item['tid'],
                        t,
                        item['tid'],
                        item['callchain'][i]['symbol']
                        )
                    converted_traces.append({"time": t, "trace_line": trace_line})
             
    # sort by time
    converted_traces.sort(key=lambda x: x['time'])
    for trace in converted_traces:
        print(trace['trace_line'])