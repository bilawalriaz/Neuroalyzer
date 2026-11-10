//! CPU topology and the thread budget for a run.
//!
//! Apple silicon and recent Intel parts mix performance and efficiency cores.
//! Thread pools that wait on each other (ONNX Runtime's intra-op pool) run at
//! the speed of their slowest member, so model threads go to performance
//! cores, while the embarrassingly parallel regex scan can use every core.

/// Logical CPUs and physical performance / efficiency cores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cores {
    /// Logical CPUs the OS will schedule us on.
    pub logical: usize,
    /// Physical performance cores (all physical cores on a homogeneous CPU).
    pub perf: usize,
    /// Physical efficiency cores (0 on a homogeneous CPU).
    pub eff: usize,
}

impl Cores {
    pub fn physical(&self) -> usize {
        self.perf + self.eff
    }
}

impl std::fmt::Display for Cores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.eff > 0 {
            write!(f, "{} performance + {} efficiency cores", self.perf, self.eff)?;
        } else {
            write!(f, "{} cores", self.perf)?;
        }
        if self.logical != self.physical() {
            write!(f, ", {} threads", self.logical)?;
        }
        Ok(())
    }
}

fn logical() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

/// Detect the CPU layout without spawning processes. Falls back to treating
/// every logical CPU as a performance core.
pub fn detect() -> Cores {
    let logical = logical();
    let c = imp::detect(logical).unwrap_or(Cores {
        logical,
        perf: logical,
        eff: 0,
    });
    // Never report more cores than we may run on (cgroups, affinity masks).
    let perf = c.perf.clamp(1, logical);
    let eff = c.eff.min(logical - perf.min(logical));
    Cores { logical, perf, eff }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::Cores;

    fn sysctl_u32(name: &str) -> Option<u32> {
        let cname = std::ffi::CString::new(name).ok()?;
        let mut v: u32 = 0;
        let mut len = std::mem::size_of::<u32>();
        // SAFETY: `v` and `len` describe a valid u32 buffer, and the name is
        // NUL-terminated. sysctlbyname writes at most `len` bytes.
        let r = unsafe {
            libc::sysctlbyname(
                cname.as_ptr(),
                (&mut v as *mut u32).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (r == 0 && len == std::mem::size_of::<u32>()).then_some(v)
    }

    pub fn detect(logical: usize) -> Option<Cores> {
        let levels = sysctl_u32("hw.nperflevels").unwrap_or(1);
        if levels >= 2 {
            let perf = sysctl_u32("hw.perflevel0.physicalcpu")? as usize;
            let eff = sysctl_u32("hw.perflevel1.physicalcpu").unwrap_or(0) as usize;
            return Some(Cores { logical, perf, eff });
        }
        let phys = sysctl_u32("hw.physicalcpu")? as usize;
        Some(Cores {
            logical,
            perf: phys,
            eff: 0,
        })
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::Cores;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::read_to_string;

    /// Parse a CPU list like "0-3,8,10-11".
    pub(super) fn cpu_list(s: &str) -> Vec<usize> {
        let mut out = vec![];
        for part in s.trim().split(',').filter(|p| !p.is_empty()) {
            match part.split_once('-') {
                Some((a, b)) => {
                    if let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                        out.extend(a..=b);
                    }
                }
                None => out.extend(part.trim().parse::<usize>().ok()),
            }
        }
        out
    }

    fn read_num(p: String) -> Option<u64> {
        read_to_string(p).ok()?.trim().parse().ok()
    }

    pub fn detect(logical: usize) -> Option<Cores> {
        let online = cpu_list(&read_to_string("/sys/devices/system/cpu/online").ok()?);
        if online.is_empty() {
            return None;
        }
        // Physical core of each logical CPU, so SMT siblings count once.
        let core_of = |cpu: usize| -> (u64, u64) {
            let t = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
            (
                read_num(format!("{t}/physical_package_id")).unwrap_or(0),
                read_num(format!("{t}/core_id")).unwrap_or(cpu as u64),
            )
        };
        // Intel hybrid exposes the two PMUs with their CPU lists.
        let class: BTreeMap<usize, bool> = if let (Ok(p), Ok(e)) = (
            read_to_string("/sys/devices/cpu_core/cpus"),
            read_to_string("/sys/devices/cpu_atom/cpus"),
        ) {
            let mut m: BTreeMap<usize, bool> = cpu_list(&p).into_iter().map(|c| (c, true)).collect();
            m.extend(cpu_list(&e).into_iter().map(|c| (c, false)));
            m
        } else {
            // ARM big.LITTLE: cpu_capacity (or max frequency) per CPU; the top
            // tier is "performance".
            let score = |cpu: usize| {
                read_num(format!("/sys/devices/system/cpu/cpu{cpu}/cpu_capacity"))
                    .or_else(|| read_num(format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq")))
            };
            let scores: Vec<(usize, Option<u64>)> = online.iter().map(|&c| (c, score(c))).collect();
            let top = scores.iter().filter_map(|s| s.1).max();
            let distinct: BTreeSet<u64> = scores.iter().filter_map(|s| s.1).collect();
            scores
                .into_iter()
                // Within 10% of the top counts as top tier: boost clocks differ per core on
                // homogeneous parts.
                .map(|(c, s)| {
                    let perf = distinct.len() < 2
                        || match (s, top) {
                            (Some(s), Some(t)) => s * 10 >= t * 9,
                            _ => true,
                        };
                    (c, perf)
                })
                .collect()
        };
        let mut perf: BTreeSet<(u64, u64)> = BTreeSet::new();
        let mut eff: BTreeSet<(u64, u64)> = BTreeSet::new();
        for &cpu in &online {
            if *class.get(&cpu).unwrap_or(&true) {
                perf.insert(core_of(cpu));
            } else {
                eff.insert(core_of(cpu));
            }
        }
        Some(Cores {
            logical,
            perf: perf.len(),
            eff: eff.len(),
        })
    }
}

#[cfg(windows)]
mod imp {
    use super::Cores;
    use std::collections::{BTreeMap, BTreeSet};
    use windows_sys::Win32::System::SystemInformation::{GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION};

    pub fn detect(logical: usize) -> Option<Cores> {
        let mut len: u32 = 0;
        // SAFETY: a null buffer with length 0 asks for the required size.
        unsafe { GetSystemCpuSetInformation(std::ptr::null_mut(), 0, &mut len, std::ptr::null_mut(), 0) };
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: `buf` is `len` bytes, as the first call requested.
        let ok = unsafe { GetSystemCpuSetInformation(buf.as_mut_ptr().cast(), len, &mut len, std::ptr::null_mut(), 0) };
        if ok == 0 {
            return None;
        }
        // EfficiencyClass: higher is faster. Count physical cores per class.
        let mut classes: BTreeMap<u8, BTreeSet<(u8, u8)>> = BTreeMap::new();
        let mut off = 0usize;
        while off + 8 <= buf.len() {
            // SAFETY: entries are laid out back to back, each starting with
            // its own Size; the bounds check above keeps the read inside
            // `buf`, and read_unaligned makes no alignment assumption.
            if off + std::mem::size_of::<SYSTEM_CPU_SET_INFORMATION>() > buf.len() {
                break;
            }
            let e: SYSTEM_CPU_SET_INFORMATION = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast()) };
            if e.Size == 0 {
                break;
            }
            if e.Type == 0 {
                // CpuSetInformation
                // SAFETY: Type 0 (CpuSetInformation) means the CpuSet variant.
                let cs = unsafe { e.Anonymous.CpuSet };
                classes
                    .entry(cs.EfficiencyClass)
                    .or_default()
                    .insert((cs.Group as u8, cs.CoreIndex));
            }
            off += e.Size as usize;
        }
        let top = *classes.keys().next_back()?;
        let perf = classes[&top].len();
        let eff = classes.iter().filter(|(k, _)| **k != top).map(|(_, v)| v.len()).sum();
        Some(Cores { logical, perf, eff })
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod imp {
    pub fn detect(_logical: usize) -> Option<super::Cores> {
        None
    }
}

/// How many CPU threads the run may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Budget {
    Auto,
    Max,
    Half,
    PCores,
    N(usize),
}

impl std::str::FromStr for Budget {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Budget::Auto),
            "max" | "all" => Ok(Budget::Max),
            "half" => Ok(Budget::Half),
            "p-cores" | "pcores" | "perf" => Ok(Budget::PCores),
            n => match n.parse::<usize>() {
                Ok(n) if n > 0 => Ok(Budget::N(n)),
                _ => Err(format!("expected a number, max, half or p-cores, got '{s}'")),
            },
        }
    }
}

impl Budget {
    /// Threads for the scan pool.
    pub fn threads(self, c: &Cores) -> usize {
        match self {
            Budget::Auto | Budget::Max => c.logical,
            Budget::Half => (c.logical / 2).max(1),
            Budget::PCores => c.perf.max(1),
            Budget::N(n) => n.min(c.logical * 4).max(1),
        }
    }
}

/// Run below normal priority so the machine stays usable: background QoS on
/// macOS (efficiency cores, throttled I/O), nice 10 on Linux, below-normal
/// priority class on Windows. Call before any worker threads start so they
/// inherit it. Best effort: failures are ignored.
pub fn lower_priority() {
    #[cfg(target_os = "macos")]
    // SAFETY: plain syscall on the current process.
    unsafe {
        libc::setpriority(libc::PRIO_DARWIN_PROCESS, 0, libc::PRIO_DARWIN_BG);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: plain syscall; on Linux it applies to the calling thread, and
    // threads created afterwards inherit it.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
    }
    #[cfg(windows)]
    // SAFETY: pseudo-handle for the current process.
    unsafe {
        use windows_sys::Win32::System::Threading::{BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, SetPriorityClass};
        SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_is_sane() {
        let c = detect();
        assert!(c.logical >= 1);
        assert!(c.perf >= 1);
        assert!(c.perf + c.eff <= c.logical);
    }

    #[test]
    fn budget_parses() {
        assert_eq!("max".parse::<Budget>(), Ok(Budget::Max));
        assert_eq!("P-Cores".parse::<Budget>(), Ok(Budget::PCores));
        assert_eq!("6".parse::<Budget>(), Ok(Budget::N(6)));
        assert!("0".parse::<Budget>().is_err());
        assert!("lots".parse::<Budget>().is_err());
        let c = Cores {
            logical: 12,
            perf: 6,
            eff: 6,
        };
        assert_eq!(Budget::Half.threads(&c), 6);
        assert_eq!(Budget::PCores.threads(&c), 6);
        assert_eq!(Budget::Max.threads(&c), 12);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_lists() {
        assert_eq!(imp::cpu_list("0-3,8,10-11\n"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(imp::cpu_list(""), Vec::<usize>::new());
    }
}
