#![windows_subsystem = "windows"]

use std::ptr::null_mut;

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxW(
        hWnd: *mut std::ffi::c_void,
        lpText: *const u16,
        lpCaption: *const u16,
        uType: u32,
    ) -> i32;
}

fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn main() {
    let text = to_wide("Mammoth");
    let caption = to_wide("Test");

    unsafe {
        MessageBoxW(
            null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            0,
        );
    }
}
