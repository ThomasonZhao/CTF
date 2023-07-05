import gdb

class Calculate(gdb.Breakpoint):
    def stop(self):
        op = hex(gdb.parse_and_eval("*(long long unsigned int *)($rsp)"))
        x1 = hex(gdb.parse_and_eval("*(long long unsigned int *)($rsp + 8)"))
        x2 = hex(gdb.parse_and_eval("*(long long unsigned int *)($rsp + 16)"))

        with open("ops.txt", "a") as f:
            f.write(f"{op}, {x1}, {x2}, ")

        return False

Calculate("*0x402099")