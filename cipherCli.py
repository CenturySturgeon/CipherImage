import click
from cipherUtils import embed_encrypted_password_in_image, decrypt_password_with_image

def prompt_for_integer(default: int) -> int:
    """Prompts the user for an integer. If he hits enter, the default value is returned, else he is prompted to confirm his input."""
    while True:
        user_input = click.prompt("Iterations", default=str(default), hide_input=True, confirmation_prompt=False)
        if not user_input.strip():  # If user hits Enter
            return default
        try:
            value = int(user_input)
            if value == default:
                return default
            else:
                confirmation_input = click.prompt("Confirm your input", hide_input=True)
                if confirmation_input == user_input:
                    return value
                else:
                    click.echo("Error: The two entered values do not match.")
        except ValueError:
            click.echo("Please enter a valid integer.")

@click.group()
def cli():
    pass

@cli.command()
# Encrypt password in image function arguments
@click.option('--master_password', prompt='Your master password', hide_input=True, confirmation_prompt=True, help='Master password used to encrypt the desired password.')
@click.option('--password', prompt='Your password to hide', hide_input=True, confirmation_prompt=True, help='The password to encrypt and hide inside the provided image.')
@click.option('--image', prompt='Path of the image', help='Path of the image to hide the password into.')
@click.option('--salt', prompt=True, default='salt_', hide_input=True, confirmation_prompt=True, help='A string value used to add randomness to the encryption process (ideally, each salt should be random and unique).')
@click.option('--iterations', default=100000, type=int, help='A higher number of iterations increases the computational cost of deriving the key, making it harder to decrypt.')

def encrypt_image(master_password, password, image, salt, iterations):
    """Encrypts a password using a key generated by the master_password, the salt, and the number of iterations, storing the output in the provided image path."""
    # Prompt the user for his iterations number, if his selection is not the default he gets prompted for confirmation.
    iterations = prompt_for_integer(iterations)
    embed_encrypted_password_in_image(master_password, password, image, salt, iterations)
    click.echo('Encrypted password hiden in the provided image.')

@cli.command()
# Decrypt password in image function arguments
@click.option('--master_password', prompt='Your master password', hide_input=True, help='Master password used to decrypt the password.')
@click.option('--image', prompt='Path of the image', help='Path of the image hiding the password.')
@click.option('--salt', prompt=True, default='salt_', hide_input=True, help='The value used to add randomness to the encryption process (the same used when encrypting the password).')
@click.option('--iterations', prompt=True, default=100000, hide_input=True, help='The number of iterations to derive the secret key (the same used when encrypting the password).')
@click.option('--copy_to_clipboard', default=False, help='Wether to show the password on the terminal or to copy it into the clipboard.')

def decrypt_image(master_password, image, salt, iterations, copy_to_clipboard):
    """Decrypts a password hiding in the provided image using a key generated by the master_password, the salt, and the number of iterations used when encrypting it."""
    decrypted_password = decrypt_password_with_image(master_password, image, salt, iterations, copy_to_clipboard)
    if copy_to_clipboard:
        click.echo('Password copied to clipboard!')
    else:
        click.echo(f'Retrieved: {decrypted_password}')

@cli.command()
# Check input function arguments
@click.option('--input', prompt=True, hide_input=True, default='', type=click.STRING, help='The input to help you see what you\'ve written into it.')

def check_input(input):
    """Simple function to review what it is you\'re writing. Especially useful when your passwords have special characters."""
    click.echo(f'You input: {input}')

if __name__ == '__main__':
    cli()