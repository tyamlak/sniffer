from binascii import a2b_hex

def dump(packet):
    for i in range(len(packet)):
        byte = packet[i]
        print('%03d  '%byte,end='')  # print hex format
        if i%16 == 15 or ( i == len(packet) - 1):
            for j in range(15-(i%16)):
                print("    ",end='')
            print("| ",end='')
            for j in range(i-(i%16),i+1):
                byte = packet[j]
                if byte > 31 and byte < 127: # if printable chars
                    bin_str = a2b_hex(hex(byte)[2:].encode())
                    print(bin_str.decode(),end='')
                else:
                    print('.',end='')
            print('')
    print('')
