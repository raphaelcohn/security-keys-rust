extern crate enum_default;
use enum_default::EnumDefault;

#[derive(EnumDefault, PartialEq)]
enum TestEnum {
    First,
    Second,
}

#[derive(EnumDefault, PartialEq)]
enum TestEnum2 {
    First,
    #[default]
    Second = 1337,
}

fn main() {
    assert!(TestEnum::default() == TestEnum::First);
    assert!(TestEnum2::default() == TestEnum2::Second);
}
