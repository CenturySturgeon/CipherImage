import click
from cipherUtils import embed_encrypted_password_in_image, decrypt_password_with_image

@click.group()
def cli():
    pass

@cli.command()
@click.option('--master_password', prompt='Your master password', help='Master password used to encrypt the desired password.')
@click.option('--password', prompt='Your password to hide', help='The password to encrypt and hide inside the provided image.')
@click.option('--image', prompt='Path of the image', help='Path of the image to hide the password into.')
@click.option('--salt', default='salt_', help='A string value used to add randomness to the encryption process (ideally, each salt should be random and unique).')
@click.option('--iterations', default=100000, help='A higher number of iterations increases the computational cost of deriving the key, making it harder to decrypt.')
def encrypt_and_hide(master_password, password, image, salt, iterations):
    embed_encrypted_password_in_image(master_password, password, image, salt, iterations)
    click.echo('Encrypted password hiden in the provided image.')

@cli.command()
@click.option('--master_password', prompt='Your master password', help='Master password used to decrypt the password.')
@click.option('--image', prompt='Path of the image.', help='Path of the image hiding the password.')
@click.option('--salt', default='salt_', help='The value used to add randomness to the encryption process (the same used when encrypting the password).')
@click.option('--iterations', default=100000, help='The number of iterations to derive the secret key (the same used when encrypting the password).')
@click.option('--copy_to_clipboard', default=False, help='Wether to show the password on the terminal or to copy it into the clipboard.')
def decrypt_image(master_password, image, salt, iterations, copy_to_clipboard):
    decrypted_password = decrypt_password_with_image(master_password, image, salt, iterations, copy_to_clipboard)
    if copy_to_clipboard:
        click.echo('Password copied to clipboard!')
    else:
        click.echo(f'Retrieved: {decrypted_password}')

if __name__ == '__main__':
    cli()