# CipherImage

![Diagram](resources/cipherImage.svg)


CipherImage is a command-line interface (CLI) utility for encrypting passwords and concealing them within images using steganography.

## Installation Instructions

### Downloading the Windows Executable

1. Make sure you're signed in to Github.
2. Go to the 'Actions' tab in this repository.
3. Find the latest workflow run and click on its name.
4. Download the zip file containing the executable.
5. Decompress the zip file and add the decompressed folder location to your path variable (you can check this [tutorial on how to do it on Windows](https://medium.com/@kevinmarkvi/how-to-add-executables-to-your-path-in-windows-5ffa4ce61a53)).
6. If everything went right, open your terminal and type "cipherImage" (the name of the .exe without the extension) and you should see something like this: 

```
Usage: cipherImage [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  check-input    Simple function to review what it is you're writing.
  decrypt-image  Decrypts a password hiding in the provided image using a...
  encrypt-image  Encrypts a password using a key generated by the...
```

Alternatively, you don't have to add the executable to your system's path variable as you can use it directly. On Windows, you'd need to open a terminal in the same folder where the executable is and run ```call cipherImage.exe``` and you'd get the same result as above.

### Building from Source

If you prefer to build the application from source:

1. Clone this repository to your local machine.
2. Ensure you have Python installed. You can download it from [here](https://www.python.org/downloads/).
3. Navigate to the cloned repository directory in your terminal.
4. Install the required dependencies by running ```pip install -r requirements.txt```.
5. Install PyInstaller by running ```pip install pyinstaller```.
6. Open a terminal at the same level as the cipherImage.spec file.
7. To build the executable, run ```pyinstaller cipherImage.spec```. The executable will be under the 'dist/'directory.

## Package Instructions

### Executable In System's Path Variable

If you followed the steps to add the executable's parent folder to your system's path variable you should be able to access the utility by typing ```cipherImage``` (or the name of the .exe file if you changed it) on your terminal.

### Executable Not In System's Path Variable

If you don't want to, or can't, get the executable file on the system's path variable, you can still use CipherImage by calling it. On Windows, just open a terminal on the folder where the .exe file is (you can do this simply by navigating to the path on the file explorer and typing ```cmd``` on the path bar), type ```call cipherImage.exe``` and hit ENTER.
With this, you should have access to the same functions as if the executable was in the system's path variable.

### Python Package

Alternatively, you can make use of CipherImage without an executable file. Just follow the "Build from Source" steps 1 through 7 first in order for this to work. After that, you can access the utilities functions by opening a terminal on the same folder where the 'cipherCli.py' file is and typing ```pythonX.X cipherCli.py``` (please note the 'X.X' in 'pythonX.X' stands for your python version, and you may not need to specify it in your system), after which you'll have access to CipherImage's functions. 

## CipherImage Usage Instructions

CipherImage comes with three simple and easy to use commands:

1. encrypt-image: Encrypts a password and hides it inside an image using steganography.
2. decrypt-image: Retrieves an encrypted password hiden inside an image and decrypts it. It allows you to specify if the password is displayed in the terminal or copied to your clipboard by setting ```--copy_to_clipboard=true```.
3. check-input: If for some reason you were to be experimenting issues when introducing any value, you can try using this command to see what is it that CipherImage is receiving as an input.
