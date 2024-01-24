import typer 
import requests
from selectolax.parser import HTMLParser
from command2 import httpssal
from command1 import salpackets
app = typer.Typer()

@app.command(help="Run a network packets sniffer.")
def netsniff():
    """
    This command runs a network packets sniffer.
    It captures and displays network packets on the terminal.
    """
    salpackets()

@app.command(help="Run an HTTP listener.")
def httplsnr():
    """
    This command starts an HTTP listener.
    It listens for incoming HTTP requests and logs them.
    """
    httpssal()


    


if __name__=='__main__':

# ASCII art for the word "SNIFFER"
    ascii_art = """
 ____        _   ____        _  __  __           
/ ___|  __ _| | / ___| _ __ (_)/ _|/ _| ___ _ __ 
\___ \ / _` | | \___ \| '_ \| | |_| |_ / _ \ '__|
 ___) | (_| | |  ___) | | | | |  _|  _|  __/ |   
|____/ \__,_|_| |____/|_| |_|_|_| |_|  \___|_| 

           ----> Python CLI Network Sniffer
                                    
           """  

# Print the ASCII art
    print(ascii_art)
    try:
        app()
    except KeyboardInterrupt:
        print("\n Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")
