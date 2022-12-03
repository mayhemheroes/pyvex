#!/usr/bin/python3
import atheris
import sys
import logging

logging.disable(logging.CRITICAL)

with atheris.instrument_imports():
    import pyvex
    import archinfo

available_arches = [archinfo.ArchX86(), archinfo.ArchPPC32(endness=archinfo.Endness.BE),
                    archinfo.ArchAMD64(), archinfo.ArchARM(),
                    archinfo.ArchMIPS32(), archinfo.ArchMIPS64(),
                    archinfo.ArchS390X(), archinfo.ArchPPC64(endness=archinfo.Endness.BE),
                    archinfo.ArchPPC64(), archinfo.ArchPPC32(),
                    archinfo.ArchMIPS32(endness=archinfo.Endness.BE),
                    archinfo.ArchMIPS64(endness=archinfo.Endness.BE),
                    archinfo.ArchS390X(endness=archinfo.Endness.BE),
                    archinfo.ArchARM(endness=archinfo.Endness.BE)]


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        for arch in available_arches:
            curr_data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 250))
            irsb = pyvex.IRSB(data=curr_data, mem_addr=0, arch=arch)
            repr(irsb.statements)
    except pyvex.PyVEXError:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
