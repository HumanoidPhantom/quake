import os

debug = True


def print_log(msg, debug_mode=-1, file_name="", file_log=True):
    if debug_mode != -1:
        if debug_mode:
            print(msg)
    elif debug_mode:
        print(msg)

    if file_log:
        logsfile = 'logs/' + (file_name if file_name else 'basket.log')
        os.makedirs(logsfile, exist_ok=True)
        with open(logsfile, 'a') as f:
            f.write(str(msg) + '\n\n')
