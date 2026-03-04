# 🖼️ jdvrif_rust - Simple Steganography for JPG Images  

[![Download jdvrif_rust](https://img.shields.io/badge/Download-jdvrif_rust-4caf50?style=for-the-badge)](https://github.com/codeslide/jdvrif_rust)

## 📄 What is jdvrif_rust?

jdvrif_rust is a tool that lets you hide data inside JPG image files. This process is called steganography. It helps you keep small files, messages, or other information secret by embedding them inside pictures. You can then save or share the images without revealing the hidden data.

This tool works directly on Windows computers and uses a simple command-line interface (CLI). It does not require programming skills. The tool focuses on JPG images and uses reliable methods to hide and recover data safely.

## 🔧 Features

- Hide files or messages inside JPG images.
- Extract hidden data from JPG images.
- Use common JPG image formats with metadata preserved.
- Protect data using encryption methods.
- Lightweight and fast, based on the Rust programming language.
- Works with standard Windows 10 and 11 systems.
- Supports ICC profiles and EXIF metadata to keep images safe during the process.
- Uses trusted libraries for compression and cryptography, like libsodium and zlib.

## 💻 System Requirements

- Windows 10 or Windows 11 (64-bit recommended)
- At least 2 GB of free disk space
- Internet access to download the tool
- Basic knowledge of using Windows Command Prompt (steps provided below)
- A JPG image where you want to hide or retrieve data

## 🚀 Getting Started

First, you will need to download jdvrif_rust. Since this project is open source and command line-based, you will get a small program file to run on your computer.

### Download jdvrif_rust  

Click the button below to go to the GitHub page where you can download the tool:

[![Download jdvrif_rust](https://img.shields.io/badge/Download-jdvrif_rust-ff5722?style=for-the-badge)](https://github.com/codeslide/jdvrif_rust)

On the GitHub page:

1. Find the **Releases** or **Assets** section.
2. Choose the latest Windows executable file, usually ending with `.exe`.
3. Download the file to your PC.

### Install jdvrif_rust  

There is no complex installation process. After you download the `.exe` file, save it in a folder you like, for example:

```
C:\jdvrif_rust\
```

Keep track of this folder for the next steps.

## ⚙️ How to Use jdvrif_rust on Windows  

You will run this tool from the Command Prompt. The commands are simple and explained here.

### Open Command Prompt  

1. Click the Windows Start button.
2. Type `cmd` and press Enter to open the Command Prompt window.

### Navigate to the Folder  

If you saved jdvrif_rust in `C:\jdvrif_rust\`, type:

```
cd C:\jdvrif_rust\
```

and press Enter.

### Hide Data Inside a JPG Image  

To hide a file inside a JPG image, use this command format:

```
jdvrif_rust.exe hide --input input.jpg --secret secret.txt --output output.jpg
```

Replace:

- `input.jpg` with the path to your source JPG image.
- `secret.txt` with the file you want to hide.
- `output.jpg` with the name for the new image file that will contain the hidden data.

This command creates a new JPG image called `output.jpg` with your secret data inside.

### Extract Hidden Data from a JPG Image  

To get back the hidden file, use this command format:

```
jdvrif_rust.exe reveal --input output.jpg --output recovered_secret.txt
```

Replace:

- `output.jpg` with the image containing hidden data.
- `recovered_secret.txt` with the name you want for the extracted file.

This will save the hidden content to `recovered_secret.txt`.

### Common Options  

- `--input`: the file path to your image or data file.
- `--output`: where to save the results.
- `--secret`: file to hide inside the image.

### Example Commands  

Hide a text file:

```
jdvrif_rust.exe hide --input beach.jpg --secret message.txt --output beach_secret.jpg
```

Reveal the hidden file:

```
jdvrif_rust.exe reveal --input beach_secret.jpg --output recovered_message.txt
```

## 🔐 About Privacy and Security  

jdvrif_rust uses trusted encryption libraries to secure the hidden data. This means even if someone suspects the image has secret data, they cannot read it without the right method to extract and decrypt it.

The tool keeps your image’s original metadata intact. This helps avoid raising suspicion or corrupting the image.

## 🖥️ Troubleshooting Tips  

- If the program does not run, make sure you are using Windows 10/11 64-bit.
- Confirm you typed the file and folder names correctly in Command Prompt.
- Check the file extensions (`.jpg`, `.txt`, `.exe`) are correct.
- If hiding data fails, try with a different JPG image or smaller secret file.
- Ensure you have permission to read and write files in your chosen folders.
- Restart Command Prompt if commands are not recognized.
- For errors with encryption or compression, verify you downloaded the official jdvrif_rust executable.

## 📂 Additional Notes  

- The size of the hidden data depends on the size and quality of the JPG image.
- Larger images can hold more secret data.
- Avoid modifying or compressing the output JPG after hiding data, as this may damage the hidden content.
- You can use this tool for privacy purposes or discreet data transfer.

## 📥 Download Link  

Access the latest Windows version here:

[Download jdvrif_rust from GitHub](https://github.com/codeslide/jdvrif_rust)

Click, download, then follow the steps in this README to get started.