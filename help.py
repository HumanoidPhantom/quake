debug = True


def print_log(msg, debug_mode=-1, file_name="", file_log=True):
    if debug_mode != -1:
        if debug_mode:
            print(msg)
    elif debug_mode:
        print(msg)

    if file_log:
        f = open(file_name if file_name else 'basket.log', 'a')
        f.write(str(msg) + '\n\n')
        f.close()
