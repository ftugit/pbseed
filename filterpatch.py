#!/usr/bin/env python3
"""Режет unified-diff на ханки и отбрасывает ханки по маркерам админ+."""
import subprocess, sys

def hunks(patch):
    head, out, cur = [], [], None
    for line in patch.splitlines(keepends=True):
        if line.startswith("@@"):
            if cur: out.append(cur)
            cur = [line]
        elif cur is not None:
            cur.append(line)
        else:
            head.append(line)
    if cur: out.append(cur)
    return head, out

def write(out_path, head, keep):
    body = "".join("".join(h) for h in keep)
    header = "".join(head).replace("/tmp/src_file", "a/pbseed-work/FILE").replace("/tmp/dst_file", "b/pbseed-work/FILE")
    open(out_path, "w").write(header + body)

src, dst, markers, out_path = sys.argv[1], sys.argv[2], sys.argv[3].split(","), sys.argv[4]
patch = subprocess.run(["diff", "-u", src, dst], capture_output=True, text=True).stdout
patch = patch.replace(src, "/tmp/src_file").replace(dst, "/tmp/dst_file")
head, hs = hunks(patch)
keep = [h for h in hs if not any(m in "".join(h) for m in markers)]
print(f"ханков всего: {len(hs)}, оставлено: {len(keep)}")
write(out_path, head, keep)
