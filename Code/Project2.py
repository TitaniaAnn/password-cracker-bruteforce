import pass_auth
import rand_pass_gen
import pass_crack


def main():
    while True:
        print("1) Password Authentication")
        print("2) Random Password Generator")
        print("3) Password Cracking")
        print("0) Exit\n")
        try:
            choice = int(input("Selection Number: "))
            if choice >= 0 and choice < 4:
                match choice:
                    case 1:
                        pass_auth.main()
                    case 2:
                        rand_pass_gen.main()
                    case 3:
                        pass_crack.main()
                    case 0:
                        return
            else:
                raise ValueError
        except ValueError:
            print("\nPick a number from 0-3\n")
            

main()
