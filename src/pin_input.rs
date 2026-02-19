use std::io::{self, Write};

/// Read a numeric PIN from stdin with masked echo (asterisks).
pub fn get_pin() -> usize {
    const MAX_PIN_LENGTH: usize = 20;
    const MAX_UINT64_STR: &str = "18446744073709551615";

    print!("\nPIN: ");
    io::stdout().flush().ok();

    let input = read_pin_masked(MAX_PIN_LENGTH);

    println!();
    io::stdout().flush().ok();

    if input.is_empty() || (input.len() == MAX_PIN_LENGTH && input.as_str() > MAX_UINT64_STR) {
        return 0;
    }

    input.parse::<usize>().unwrap_or(0)
}

#[cfg(unix)]
fn read_pin_masked(max_len: usize) -> String {
    use libc::{read as libc_read, tcgetattr, tcsetattr, termios, ECHO, ICANON, STDIN_FILENO, TCSANOW};
    use std::mem::MaybeUninit;

    let mut input = String::new();

    unsafe {
        // Save old terminal settings and set raw mode.
        let mut old_termios = MaybeUninit::<termios>::zeroed().assume_init();
        tcgetattr(STDIN_FILENO, &mut old_termios);
        let mut new_termios = old_termios;
        new_termios.c_lflag &= !(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

        let mut ch: u8 = 0;
        while input.len() < max_len {
            let bytes_read = libc_read(STDIN_FILENO, &mut ch as *mut u8 as *mut libc::c_void, 1);
            if bytes_read <= 0 {
                continue;
            }
            if ch >= b'0' && ch <= b'9' {
                input.push(ch as char);
                print!("*");
                io::stdout().flush().ok();
            } else if (ch == b'\x08' || ch == 127) && !input.is_empty() {
                print!("\x08 \x08");
                io::stdout().flush().ok();
                input.pop();
            } else if ch == b'\n' {
                break;
            }
        }

        // Restore old terminal settings.
        tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
    }
    input
}

#[cfg(windows)]
fn read_pin_masked(max_len: usize) -> String {
    // On Windows, use _getch from msvcrt.
    extern "C" {
        fn _getch() -> i32;
    }

    let mut input = String::new();
    while input.len() < max_len {
        let ch = unsafe { _getch() } as u8;
        if ch >= b'0' && ch <= b'9' {
            input.push(ch as char);
            print!("*");
            io::stdout().flush().ok();
        } else if ch == b'\x08' && !input.is_empty() {
            print!("\x08 \x08");
            io::stdout().flush().ok();
            input.pop();
        } else if ch == b'\r' {
            break;
        }
    }
    input
}
