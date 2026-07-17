// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Minimal Rust program to trace with uprobe.  Build with:
 *   rustc -g target.rs -o target
 * The `slow_function` has a known symbol we attach a uprobe to.
 */
use std::time::Duration;

#[no_mangle]
pub extern "C" fn slow_function(x: u64) -> u64 {
    std::thread::sleep(Duration::from_millis(10 * x));
    x * 2
}

fn main() {
    let mut sum: u64 = 0;
    for i in 0..10u64 {
        sum = sum.wrapping_add(slow_function(i));
    }
    println!("sum = {}", sum);
}
