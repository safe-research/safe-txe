macro_rules! verify {
    ($cond:expr $(, $msg:literal)?) => {{
        #[cfg(debug_assertions)]
        {
            assert!($cond $(, $msg)?);
        }
        #[cfg(not(debug_assertions))]
        {
            let cond = $cond;
            if !cond {
                ::std::process::abort();
            }
        }
    }};
}
pub(crate) use verify;

macro_rules! unwrap {
    ($res:expr) => {{
        #[cfg(debug_assertions)]
        {
            ($res).unwrap()
        }
        #[cfg(not(debug_assertions))]
        {
            match $res {
                Ok(v) => v,
                Err(_) => ::std::process::abort(),
            }
        }
    }};
}
pub(crate) use unwrap;
