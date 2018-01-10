debug = True


def print_log(msg, debug_mode=-1):
    f = open('basket.log', 'a')
    if debug_mode != -1:
        if debug_mode:
            f.write(str(msg) + '\n\n')
            print(msg)
    elif debug_mode:
        print(msg)
        f.write(str(msg) + '\n\n')
    f.close()
