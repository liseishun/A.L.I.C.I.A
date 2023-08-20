import click
import hashlib
import re
import bcrypt



ASCII_ART1 = r"""  /$$$$$$      /$$           /$$$$$$      /$$$$$$     /$$$$$$      /$$$$$$ 
 /$$__  $$    | $$          |_  $$_/     /$$__  $$   |_  $$_/     /$$__  $$
| $$  \ $$    | $$            | $$      | $$  \__/     | $$      | $$  \ $$
| $$$$$$$$    | $$            | $$      | $$           | $$      | $$$$$$$$
| $$__  $$    | $$            | $$      | $$           | $$      | $$__  $$
| $$  | $$    | $$            | $$      | $$    $$     | $$      | $$  | $$
| $$  | $$ /$$| $$$$$$$$ /$$ /$$$$$$ /$$|  $$$$$$//$$ /$$$$$$ /$$| $$  | $$
|__/  |__/|__/|________/|__/|______/|__/ \______/|__/|______/|__/|__/  |__/
                                                                           
                                                                           
                                                                           
                                                                           This project made by Liseishun"""

ASCII_ART2  =r"""  ______   _______   ________   ______  ________  ________        _______    ______    ______    ______   __       __   ______   _______   _______  
 /      \ |       \ |        \ /      \|        \|        \      |       \  /      \  /      \  /      \ |  \  _  |  \ /      \ |       \ |       \ 
|  $$$$$$\| $$$$$$$\| $$$$$$$$|  $$$$$$\\$$$$$$$$| $$$$$$$$      | $$$$$$$\|  $$$$$$\|  $$$$$$\|  $$$$$$\| $$ / \ | $$|  $$$$$$\| $$$$$$$\| $$$$$$$\
| $$   \$$| $$__| $$| $$__    | $$__| $$  | $$   | $$__          | $$__/ $$| $$__| $$| $$___\$$| $$___\$$| $$/  $\| $$| $$  | $$| $$__| $$| $$  | $$
| $$      | $$    $$| $$  \   | $$    $$  | $$   | $$  \         | $$    $$| $$    $$ \$$    \  \$$    \ | $$  $$$\ $$| $$  | $$| $$    $$| $$  | $$
| $$   __ | $$$$$$$\| $$$$$   | $$$$$$$$  | $$   | $$$$$         | $$$$$$$ | $$$$$$$$ _\$$$$$$\ _\$$$$$$\| $$ $$\$$\$$| $$  | $$| $$$$$$$\| $$  | $$
| $$__/  \| $$  | $$| $$_____ | $$  | $$  | $$   | $$_____       | $$      | $$  | $$|  \__| $$|  \__| $$| $$$$  \$$$$| $$__/ $$| $$  | $$| $$__/ $$
 \$$    $$| $$  | $$| $$     \| $$  | $$  | $$   | $$     \      | $$      | $$  | $$ \$$    $$ \$$    $$| $$$    \$$$ \$$    $$| $$  | $$| $$    $$
  \$$$$$$  \$$   \$$ \$$$$$$$$ \$$   \$$   \$$    \$$$$$$$$       \$$       \$$   \$$  \$$$$$$   \$$$$$$  \$$      \$$  \$$$$$$  \$$   \$$ \$$$$$$$ 
                                                                                                                                                    
                                                                                                                                                    
                                                                                                                                                    """

ASCII_ART3 =r"""  ______   ________  __    __  ________  _______    ______  ________  ________        __    __   ______    ______   __    __ 
 /      \ |        \|  \  |  \|        \|       \  /      \|        \|        \      |  \  |  \ /      \  /      \ |  \  |  \
|  $$$$$$\| $$$$$$$$| $$\ | $$| $$$$$$$$| $$$$$$$\|  $$$$$$\\$$$$$$$$| $$$$$$$$      | $$  | $$|  $$$$$$\|  $$$$$$\| $$  | $$
| $$ __\$$| $$__    | $$$\| $$| $$__    | $$__| $$| $$__| $$  | $$   | $$__          | $$__| $$| $$__| $$| $$___\$$| $$__| $$
| $$|    \| $$  \   | $$$$\ $$| $$  \   | $$    $$| $$    $$  | $$   | $$  \         | $$    $$| $$    $$ \$$    \ | $$    $$
| $$ \$$$$| $$$$$   | $$\$$ $$| $$$$$   | $$$$$$$\| $$$$$$$$  | $$   | $$$$$         | $$$$$$$$| $$$$$$$$ _\$$$$$$\| $$$$$$$$
| $$__| $$| $$_____ | $$ \$$$$| $$_____ | $$  | $$| $$  | $$  | $$   | $$_____       | $$  | $$| $$  | $$|  \__| $$| $$  | $$
 \$$    $$| $$     \| $$  \$$$| $$     \| $$  | $$| $$  | $$  | $$   | $$     \      | $$  | $$| $$  | $$ \$$    $$| $$  | $$
  \$$$$$$  \$$$$$$$$ \$$   \$$ \$$$$$$$$ \$$   \$$ \$$   \$$   \$$    \$$$$$$$$       \$$   \$$ \$$   \$$  \$$$$$$  \$$   \$$
                                                                                                                             
                                                                                                                             
                                                                                                                             """


PASSWORD_FILE = "temp_password.txt"

PROMPT_NAME = '\nPlease enter your name'
PROMPT_PASSWORD = '\nPlease enter your password'
HELLO_MSG = 'Hello, {name}! Please type python script_name.py --help for more options.'
STRONG_PASS_MSG = 'Strong password'
WEAK_PASS_MSG = 'Weak password. Please try again.'
HASHED_PASS_MSG = 'Your hashed password is: {hashed_password}'

def save_password(password):
    """
    Save password to a temporary file.
    """
    with open(PASSWORD_FILE, 'w') as file:
        file.write(password)

def retrieve_password():
    """
    Retrieve password from a temporary file.
    """
    try:
        with open(PASSWORD_FILE, 'r') as file:
            return file.readline().strip()
    except FileNotFoundError:
        return None

@click.command()
@click.option('--generate_hash', is_flag=True, help='Change a password to a hashed password.')
@click.option('--generate_pass', is_flag=True, help='Generate password and check the strength of the provided password.')
def main(generate_hash, generate_pass):

    # If the user wants to check the password's strength
    if generate_pass:
        click.echo(ASCII_ART2)
        get_and_check_password()
        return  # Exit after checking password

    # If the user wants to generate a hash for the stored password
    if generate_hash:
        click.echo(ASCII_ART3)
        password_to_hash = retrieve_password()  # Retrieve password from file
        if not password_to_hash:
            click.echo("No stored password found. Please check its strength first.")
            return
        hashed_password = hash_password(password_to_hash)
        click.echo(HASHED_PASS_MSG.format(hashed_password=hashed_password))
        return  # Exit after displaying the hashed password

    # If neither options are provided, prompt for name and display the greeting
    click.echo(ASCII_ART1)
    name = click.prompt(PROMPT_NAME, type=str)
    click.echo(HELLO_MSG.format(name=name))


def get_and_check_password():
    """
    Prompt the user for a password and check its strength.
    """
    while True:
        password = click.prompt(PROMPT_PASSWORD, hide_input=True, confirmation_prompt=True)
        is_strong = check_password_strength(password)  # Store result once
        if is_strong:
            click.echo(STRONG_PASS_MSG)
            save_password(password)  # Save password to file
            break  
        else:
            click.echo(WEAK_PASS_MSG)

def hash_password(password):
    """
    Hashes a password using bcrypt and returns the hashed password.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt).decode()
    return hashed_password

def check_password_strength(password):
    """
    Checks the strength of a password based on various criteria.
    """
    MIN_LENGTH = 12  
    SPECIAL_CHARS = r"!@#$%^&*()-_=+[]{}|;:'<>,.?~"  

    if len(password) < MIN_LENGTH:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in SPECIAL_CHARS for char in password):
        return False
    if any(password[i:i+4] == password[i+4:i+8] for i in range(len(password) - 7)):
        return False
    if re.search(r'(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)', password.lower()):
        return False
    
    return True

if __name__ == "__main__":
    main()