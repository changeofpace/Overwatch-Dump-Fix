# work in progress, do not use on an .idb without backing it up.

# there are several unreferenced strings in IDA of the format \btext\b.
# this script attempts to label these strings using the \b prefix.
# as of 12.13.2016 most of the identified strings appear to be "profanity filter" words.

import idautils

# "0\b" in hex
blizzard_string_prefix = "00 5C 62"

def print_segment(segment):
    print "%X - %X  %s" % (segment, SegEnd(segment), SegName(segment))

def main():
    data_segments = [s for s in Segments() if SegName(s) in [".data", ".rdata"]]
    # data_ranges =   [(s, SegEnd(s)) for s in data_segments]
    # map(print_segment, data_segments)
    ea = 1
    matches = []
    while ea != BADADDR:
        ea = FindBinary(ea, SEARCH_DOWN | SEARCH_NEXT, blizzard_string_prefix)
        if isData(ea):
            matches.append(ea)
    for match in matches:
        if MakeStr(match + 1, BADADDR) is 1:
            print "%X  %s" % (match, GetString(match))

if __name__ == "__main__":
    main()
