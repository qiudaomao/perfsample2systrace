#!/usr/bin/env python3
import re
import argparse
import os

def parse_perf_data(lines):
    stack=[]
    output_lines = []
    output_lines.append("meta_info:")
    output_lines.append("  trace_offcpu: false")
    output_lines.append("  event_type: cpu-cycles")
    output_lines.append("  android_sdk_version: 35")
    output_lines.append("  android_build_type: userdebug")
    for line in lines:
        m = re.match(r'(.*) +([0-9]+) \[...\] +([0-9]+\.[0-9]+): +([0-9]+) (.*):', line)
        if m:
            output_lines.append("sample:")
            event_count=int(m.group(4))
            output_lines.append("  event_type: %s"%(m.group(5)))
            output_lines.append("  time: %d"%(float(m.group(3))*1000000000))
            output_lines.append("  event_count: %d"%(event_count))
            output_lines.append("  thread_id: %s"%(m.group(2)))
            output_lines.append("  thread_name: %s"%(m.group(1).rstrip()))
            continue
        m = re.match(r'(.*) +([0-9]+) +([0-9]+\.[0-9]+): +([0-9]+) (.*):', line)
        if m:
            output_lines.append("sample:")
            event_count=int(m.group(4))
            output_lines.append("  event_type: %s"%(m.group(5)))
            output_lines.append("  time: %d"%(float(m.group(3))*1000000000))
            output_lines.append("  event_count: %d"%(event_count))
            output_lines.append("  thread_id: %s"%(m.group(2)))
            output_lines.append("  thread_name: %s"%(m.group(1).rstrip()))
            continue
        if re.match(r'^$', line):
            first=True
            for s in stack:
                m = re.match(r'\s*([0-9a-z]+) (.*) \((.*)\)', s)
                if m:
                    addr=m.group(1)
                    symbol=m.group(2)
                    vaddr_file=m.group(3)
                    if first:
                        first=False
                        output_lines.append("  vaddr_in_file: %s" % addr)
                        output_lines.append("  symbol: %s" % symbol)
                        output_lines.append("  callchain:")
                    else:
                        output_lines.append("    vaddr_in_file: %s" % addr)
                        output_lines.append("    file: %s" % vaddr_file)
                        output_lines.append("    symbol: %s" % symbol)
            stack=[]
            continue
        stack.append(line)
    return output_lines

def merge(perf_sample_file='sample.txt', trace_file=None, out_file=None, filter_tid=''):
    file = open(perf_sample_file, 'r')
    trace_file_fd = None
    out_file_fd = None
    if not file:
        print("failed to open perf sample file%s"%perf_sample_file)
        return
    # print("trace_file %s" % trace_file)
    if trace_file:
        trace_file_fd = open(trace_file, 'r', errors='ignore')
        if not trace_file_fd:
            print("failed to open trace file %s"%trace_file)
            return
    if out_file:
        out_file_fd = open(out_file, 'w')
        if not out_file_fd:
            print("failed to open out file %s"%out_file)
            return

    if file:
        lines = file.readlines()
        if len(lines) > 0 and lines[0].strip() != "meta_info:":
            lines = parse_perf_data(lines)
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
                if tid and (len(filter_tid) == 0 or tid == filter_tid):
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
                    if trace_file_fd:
                        tid = "%d" % (9000000 + int(tid))
                elif line.strip().startswith("thread_name:"):
                    process_name = line.split(":")[1].strip()
                elif line.strip().startswith("time:"):
                    time = float(line.split(":")[1].strip()) / 1e9  # Convert nanoseconds to seconds
                elif line.strip().startswith("event_count:"):
                    event_count = int(line.split(":")[1].strip())
                elif line.strip().startswith("symbol:"):
                    symbol = re.match(" *symbol:(.*)$", line).group(1).strip()
                    file_name = file
                    if file.startswith("/"):
                        file_name = os.path.basename(file)
                    if symbol == '[unknown]' or symbol.startswith('!!!'):
                        # get file name from path
                        # if vaddr_in_file.find("ffe377e40378") != -1:
                            # print("symbol %s file %s filename %s vaddr_in_file %s" % (symbol, file, file_name, vaddr_in_file))
                        symbol = ("%s:0x%s"%(file_name, vaddr_in_file)).replace('[kernel.kallsyms]', 'kernel')
                    else:
                        symbol = ("%s(%s)"%(symbol, file_name)).replace('[kernel.kallsyms]', 'kernel')
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
                # symbol_ = line.split(":")[1].strip()
                symbol_ = re.match(" *symbol:(.*)$", line).group(1).strip()
                file_ = lines[line_idx - 1].split(":")[1].strip()
                vaddr_in_file_ = lines[line_idx - 2].split(":")[1].strip()
                file_name = file_
                if file_.startswith("/"):
                    file_name = os.path.basename(file_)
                if symbol_== '[unknown]' or symbol_.startswith('!!!'):
                    symbol_= ("%s:0x%s"%(file_name, vaddr_in_file_)).replace('[kernel.kallsyms]', 'kernel')
                else:
                    symbol_ = ("%s(%s)"%(symbol_, file_name)).replace('[kernel.kallsyms]', 'kernel')
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
                converted_traces.append({"time": item['time'], "trace_line": trace_line, "consumed": False})
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
                        converted_traces.append({"time": item['time'], "trace_line": trace_line, "consumed": False})
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
                        converted_traces.append({"time": t, "trace_line": trace_line, "consumed":False})

        # sort by time
        converted_traces.sort(key=lambda x: x['time'])
                 
        # here parse and append trace_event from trace_file
        prev_t = None
        prev_consumed_idx = 0
        if trace_file_fd:
            trace_lines = trace_file_fd.readlines()
            for trace_line_idx in range(len(trace_lines)):
                trace_line = trace_lines[trace_line_idx]
                # parse 
                # {threadName}-{tid} ({tid}) [{cpu}] .....    {time}: {trace_content}
                t = None
                m = re.match(r'(.*)-([0-9-]+) +\(([ 0-9]+)\) \[([0-9]+)\] ..... *([0-9]+\.[0-9]+): (.*)', trace_line)
                if m:
                    t = float(m.group(5))
                m1 = re.match(r'(.*)-([0-9-]+) +\[([0-9]+)\] ..... *([ 0-9]+\.[0-9]+): (.*)', trace_line)
                if m1:
                    t = float(m1.group(5))

                if t and prev_t:
                    # print("find t %.6f prev_t %.6f" % (t, prev_t))
                    # insert converted_traces into current trace lines by time
                    for i in range(prev_consumed_idx, len(converted_traces)):
                        if not converted_traces[i]['consumed']:
                            if converted_traces[i]['time'] >= prev_t and converted_traces[i]['time'] <= t:
                                # print("match one %.6f [%.6f, %.6f]" % (converted_traces[i]['time'], prev_t, t))
                                prev_consumed_idx = i
                                converted_traces[i]['consumed'] = True
                                if out_file_fd:
                                    out_file_fd.write(converted_traces[i]['trace_line'] + "\n")
                                else:
                                    print(converted_traces[i]['trace_line'])
                            elif converted_traces[i]['time'] <= t:
                                converted_traces[i]['consumed'] = True
                                prev_consumed_idx = i
                            else:
                                break
                if t:
                    prev_t = t

                if out_file_fd:
                    out_file_fd.write(trace_line)
                else:
                    print(trace_line)
            # for i in range(len(converted_traces)):
            #     if not converted_traces[i]['consumed']:
            #         converted_traces[i]['consumed'] = True
            #         if out_file_fd:
            #             out_file_fd.write("insert: %s" % converted_traces[i]['trace_line'])
            #         else:
            #             print(converted_traces[i]['trace_line'])
            #         break
        else:
            for trace in converted_traces:
                if out_file_fd:
                    out_file_fd.write(trace['trace_line'] + "\n")
                else:
                    print(trace['trace_line'])
    # close opened files
    if trace_file_fd:
        trace_file_fd.close()
    if out_file_fd:
        out_file_fd.close()

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="details", formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("-p", "--perf_sample_file", required=True, help='''path to the perf sample or script file
capture by perf:
    perf record -o /data/perf.data -e cpu-cycles -F 10000 -a -g -- sleep 10
    perf script -i /data/perf.data > /data/sample.txt
    perf script -i /data/perf.data --symfs=/data > /data/sample.txt #path for unstripped files
or capture by simpleperf:
    simpleperf record -a -e cpu-cycles -f 10000 --call-graph fp -o /data/local/tmp/perf.data -- sleep 10
    simpleperf report-sample --show-callchain -i /data/local/tmp/perf.data -o /data/local/tmp/sample.txt''')
    ap.add_argument("-t", "--trace_file", required=False, help="path to the trace file will merge together, ftrace or systrace text content")
    ap.add_argument("-o", "--out_file", required=False, help="path to the output file")
    ap.add_argument("-f", "--filter_tid", required=False, default='', help="filter perf sample by tid")
    args = vars(ap.parse_args())
    merge(args['perf_sample_file'], args['trace_file'], args['out_file'], args['filter_tid'])
