use super::*;

fn read_single_byte() -> Option<u8> {
    let mut ch = 0u8;
    // SAFETY: reading one byte from STDIN into valid writable memory.
    let bytes_read = unsafe {
        libc::read(
            libc::STDIN_FILENO,
            &mut ch as *mut u8 as *mut libc::c_void,
            1usize,
        )
    };

    if bytes_read == 0 {
        return None;
    }
    if bytes_read < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error();
        if errno == Some(libc::EINTR) {
            return Some(0xFF);
        }
        return None;
    }

    Some(ch)
}

pub(super) fn get_pin() -> u64 {
    const MAX_PIN_LENGTH: usize = 20;
    const MAX_U64_STR: &[u8] = b"18446744073709551615";

    print!("\nPIN: ");
    let _ = std::io::stdout().flush();

    // SAFETY: querying whether STDIN is attached to a TTY.
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    let _termios_guard = TermiosGuard::new();

    let mut input = Vec::<u8>::new();
    while input.len() < MAX_PIN_LENGTH {
        let Some(ch) = read_single_byte() else {
            break;
        };

        if ch == 0xFF {
            continue;
        }

        if ch.is_ascii_digit() {
            input.push(ch);
            if is_tty {
                print!("*");
                let _ = std::io::stdout().flush();
            }
        } else if (ch == b'\x08' || ch == 127) && !input.is_empty() {
            if is_tty {
                print!("\x08 \x08");
                let _ = std::io::stdout().flush();
            }
            input.pop();
        } else if ch == b'\n' || ch == b'\r' {
            break;
        }
    }

    println!();
    let _ = std::io::stdout().flush();

    let wipe_and_zero = |buf: &mut Vec<u8>| {
        if !buf.is_empty() {
            memzero(buf);
        }
        buf.clear();
    };

    if input.is_empty() || (input.len() == MAX_PIN_LENGTH && input.as_slice() > MAX_U64_STR) {
        wipe_and_zero(&mut input);
        return 0;
    }

    let parsed = std::str::from_utf8(&input)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    wipe_and_zero(&mut input);
    parsed
}
