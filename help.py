debug = True


def print_log(msg, debug_mode=-1):
    if debug_mode != -1:
        if debug_mode:
            print(msg)
    elif debug_mode:
        print(msg)
