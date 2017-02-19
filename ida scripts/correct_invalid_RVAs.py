# No longer necessary with release v2.0.
#
# This script corrects invalid RVAs by rebasing the .idb to Overwatch's imagebase.
# See plugin output:
#   [Overwatch Dump Fix] IDA Pro Info:
#   [Overwatch Dump Fix]     overwatch base address = 000000013F790000


import idc
import idaapi


def main():
    overwatch_imagebase = idc.AskAddr(idc.BADADDR, "Enter Overwatch's base address.")
    if overwatch_imagebase and overwatch_imagebase is not idc.BADADDR:
        delta = overwatch_imagebase - idaapi.get_imagebase()
        status = rebase_program(delta, idc.MSF_NOFIX)
        if status is not idc.MOVE_SEGM_OK:
            print "rebase_program failed %d." % (status)


if __name__ == '__main__':
    main()