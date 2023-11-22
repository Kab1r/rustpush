use std::{collections::HashMap, mem::size_of, sync::Arc};

use unicorn_engine::{
    unicorn_const::{Arch, Mode, Permission},
    RegisterX86, Unicorn,
};

#[derive(Debug, Clone)]
pub(crate) enum CfObject {
    String(String),
    Data(Vec<u8>),
    Dictionary(HashMap<String, CfObject>),
}

//#[derive(Debug)]
pub(crate) struct Jelly<'a> {
    pub(crate) binary: &'a [u8],
    pub(crate) hooks: HashMap<String, Box<dyn Hook>>,
    pub(crate) resolved_hooks: HashMap<u64, String>,
    pub(crate) uc: Unicorn<'a, ()>,
    heap_size: u64,
    pub(crate) cf_objects: Vec<CfObject>,
    pub(crate) eth_iterator_hack: bool,
}

struct VirtualInstruction<'a, 'b, D> {
    uc: &'a mut Unicorn<'b, D>,
}

const ARG_REGISTERS: [RegisterX86; 6] = [
    RegisterX86::RDI,
    RegisterX86::RSI,
    RegisterX86::RDX,
    RegisterX86::RCX,
    RegisterX86::R8,
    RegisterX86::R9,
];

const STOP_ADDR: u64 = 0x0090_0000;

impl<'a, 'b, D> VirtualInstruction<'a, 'b, D> {
    fn new(uc: &'b mut Unicorn<'b, D>) -> Self {
        Self { uc }
    }
    fn push(&mut self, value: u64) {
        self.uc.reg_write(
            RegisterX86::ESP,
            self.uc.reg_read(RegisterX86::ESP).unwrap() - 8,
        );
        self.uc
            .mem_write(
                self.uc.reg_read(RegisterX86::ESP).unwrap(),
                &value.to_le_bytes(),
            )
            .unwrap();
    }
    fn pop(self) -> u64 {
        let mut buf = [0u8; 8];
        self.uc
            .mem_read(self.uc.reg_read(RegisterX86::ESP).unwrap(), &mut buf)
            .unwrap();
        self.uc.reg_write(
            RegisterX86::ESP,
            self.uc.reg_read(RegisterX86::ESP).unwrap() + 8,
        );
        u64::from_le_bytes(buf)
    }
    fn set_args(&mut self, args: &[u64]) {
        for (i, arg) in args.iter().enumerate() {
            if i < 6 {
                self.uc.reg_write(ARG_REGISTERS[i], *arg);
            } else {
                self.push(*arg);
            }
        }
    }
    fn call(&mut self, addr: u64, args: &[u64]) -> u64 {
        self.push(STOP_ADDR);
        self.set_args(args);
        self.uc.emu_start(addr, STOP_ADDR, 0, 0).unwrap();
        self.uc.reg_read(RegisterX86::RAX).unwrap()
    }
}

pub(super) trait Hook {
    fn hook(&self, jelly: &mut Jelly, args: &[u64]) -> u64;
    fn args(&self) -> usize;
}

impl<'a> Jelly<'a> {
    const HOOK_BASE: u64 = 0xD0_00_00;
    const HOOK_SIZE: usize = 0x10_00_00;
    const HEAP_BASE: u64 = 0x00_40_00;
    pub(crate) fn new(binary: &'a [u8]) -> Self {
        Self {
            binary,
            hooks: HashMap::new(),
            resolved_hooks: HashMap::new(),
            uc: Unicorn::new(Arch::X86, Mode::MODE_64).unwrap(),
            heap_size: 0,
            cf_objects: Vec::new(),
            eth_iterator_hack: false,
        }
    }
    pub(crate) fn setup(&mut self, hooks: HashMap<String, Box<dyn Hook + 'static>>) {
        let instr = VirtualInstruction::new(&mut self.uc);
        for (name, hook) in hooks {
            self.hooks.insert(name.clone(), hook);
        }
        self.uc
            .mem_map(Self::HOOK_BASE, Self::HOOK_SIZE, Permission::ALL);
        self.uc
            .mem_write(Self::HOOK_BASE, b"\xc3".repeat(Self::HOOK_SIZE).as_slice())
            .unwrap();
        self.uc.add_code_hook(
            Self::HOOK_BASE,
            Self::HOOK_BASE + Self::HOOK_SIZE as u64,
            |uc, addr, size| {
                if let Some(name) = self.resolved_hooks.get(&addr) {
                    self.hooks[name].hook(self, &[]);
                }
            },
        );
    }
    pub(crate) fn malloc(&mut self, size: u64) -> u64 {
        let addr = Self::HEAP_BASE + self.heap_size;
        self.heap_size += size;
        addr
    }
    pub(crate) fn parse_cfstr_ptr(&mut self, ptr: u64) -> String {
        let mut buf = [0u8; 32];
        self.uc.mem_read(ptr, &mut buf).unwrap();
        let [isa, flags, str_ptr, length] = *buf
            .chunks(8)
            .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();
        let mut str_buf = vec![0u8; length as usize];
        self.uc.mem_read(str_ptr, &mut str_buf).unwrap();
        String::from_utf8(str_buf).unwrap()
    }
}
