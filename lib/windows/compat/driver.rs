//! Installable-driver API boundary. No driver modules are registered yet;
//! opening fails and invalid handles never invoke a driver callback.
#[unsafe(no_mangle)]
pub extern "system" fn OpenDriver(_name: u32, _section: u32, _parameter: u32) -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn CloseDriver(_driver: u32, _a: u32, _b: u32) -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn SendDriverMessage(_driver: u32, _message: u32, _a: u32, _b: u32) -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn GetDriverModuleHandle(_driver: u32) -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "system" fn DefDriverProc(
    _id: u32,
    _driver: u32,
    message: u32,
    _a: u32,
    _b: u32,
) -> u32 {
    // LOAD, ENABLE, DISABLE, FREE, INSTALL and REMOVE have default success.
    // OPEN, CLOSE, configuration and driver-specific messages require a driver.
    match message {
        1 | 2 | 5 | 6 | 9 | 10 => 1,
        _ => 0,
    }
}
