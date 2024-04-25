# Unity Game Anti-Cheat Bypass Console

This console application demonstrates a method to bypass anti-cheat mechanisms in Unity games. It utilizes shellcode injection techniques to execute custom code within the game process, effectively circumventing anti-cheat measures.

## How It Works

1. **Initialization**: The application initializes by locating the process ID of the Unity game.
2. **Process Manipulation**: After locating the game process, the application opens a handle to it using Windows API functions.
3. **Shellcode Execution**: Custom shellcode is read from a binary file and injected into the game process.
4. **Remote Thread Creation**: A remote thread is created within the game process, executing the injected shellcode.
5. **Anti-Cheat Bypass**: The shellcode performs actions necessary to bypass anti-cheat mechanisms, enabling cheating within the game.

## Prerequisites

- Windows operating system
- Unity game with anti-cheat measures
- Shellcode file (*.bin) containing the custom code to execute within the game process

## Usage

1. Ensure that the shellcode file is located in the specified directory (`C:\ShellcodeDirectory` by default).
2. Compile and run the console application.
3. Follow the on-screen instructions to bypass the Unity game anti-cheat.

## Notes

- This application is for educational and research purposes only. Usage for cheating in online games or other unethical activities is strictly prohibited.
- Use caution when executing custom shellcode within game processes, as it may lead to unintended consequences or system instability.
