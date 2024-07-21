// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

pub use self::imp::*;

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(clippy::absolute_paths)]
#[allow(clippy::transmute_ptr_to_ref)]
#[allow(clippy::upper_case_acronyms)]
#[warn(single_use_lifetimes)]
mod imp {
    #[allow(unused_imports)]
    use super::*;
    use libbpf_rs::libbpf_sys;
    use libbpf_rs::skel::OpenSkel;
    use libbpf_rs::skel::Skel;
    use libbpf_rs::skel::SkelBuilder;

    fn build_skel_config(
    ) -> libbpf_rs::Result<libbpf_rs::__internal_skel::ObjectSkeletonConfig<'static>> {
        let mut builder = libbpf_rs::__internal_skel::ObjectSkeletonConfigBuilder::new(DATA);
        builder
            .name("execve_bpf")
            .map("ringbuf", false)
            .map("execve_b.rodata", false)
            .prog("detect_execve");

        builder.build()
    }

    #[derive(Default)]
    pub struct ExecveSkelBuilder {
        pub obj_builder: libbpf_rs::ObjectBuilder,
    }

    impl<'a> SkelBuilder<'a> for ExecveSkelBuilder {
        type Output = OpenExecveSkel<'a>;
        fn open(self) -> libbpf_rs::Result<OpenExecveSkel<'a>> {
            let opts = *self.obj_builder.opts();
            self.open_opts(opts)
        }

        fn open_opts(
            self,
            open_opts: libbpf_sys::bpf_object_open_opts,
        ) -> libbpf_rs::Result<OpenExecveSkel<'a>> {
            let mut skel_config = build_skel_config()?;

            let ret =
                unsafe { libbpf_sys::bpf_object__open_skeleton(skel_config.get(), &open_opts) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            let obj = unsafe { libbpf_rs::OpenObject::from_ptr(skel_config.object_ptr())? };

            #[allow(unused_mut)]
            let mut skel = OpenExecveSkel {
                obj,
                // SAFETY: Our `struct_ops` type contains only pointers,
                //         which are allowed to be NULL.
                // TODO: Generate and use a `Default` representation
                //       instead, to cut down on unsafe code.
                struct_ops: unsafe { std::mem::zeroed() },
                skel_config,
            };

            Ok(skel)
        }

        fn object_builder(&self) -> &libbpf_rs::ObjectBuilder {
            &self.obj_builder
        }
        fn object_builder_mut(&mut self) -> &mut libbpf_rs::ObjectBuilder {
            &mut self.obj_builder
        }
    }

    pub struct OpenExecveMapsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenExecveMapsMut<'_> {
        pub fn ringbuf(&mut self) -> &mut libbpf_rs::OpenMap {
            self.inner.map_mut("ringbuf").unwrap()
        }

        pub fn rodata(&mut self) -> &mut libbpf_rs::OpenMap {
            self.inner.map_mut("execve_b.rodata").unwrap()
        }
    }

    pub struct OpenExecveMaps<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenExecveMaps<'_> {
        pub fn ringbuf(&self) -> &libbpf_rs::OpenMap {
            self.inner.map("ringbuf").unwrap()
        }

        pub fn rodata(&self) -> &libbpf_rs::OpenMap {
            self.inner.map("execve_b.rodata").unwrap()
        }
    }

    pub struct OpenExecveProgs<'a> {
        inner: &'a libbpf_rs::OpenObject,
    }

    impl OpenExecveProgs<'_> {
        pub fn detect_execve(&self) -> &libbpf_rs::OpenProgram {
            self.inner.prog("detect_execve").unwrap()
        }
    }

    pub struct OpenExecveProgsMut<'a> {
        inner: &'a mut libbpf_rs::OpenObject,
    }

    impl OpenExecveProgsMut<'_> {
        pub fn detect_execve(&mut self) -> &mut libbpf_rs::OpenProgram {
            self.inner.prog_mut("detect_execve").unwrap()
        }
    }

    pub mod execve_types {
        #[allow(unused_imports)]
        use super::*;
        #[derive(Debug, Copy, Clone)]
        #[repr(C)]
        pub struct rodata {}

        #[derive(Debug, Clone)]
        #[repr(C)]
        pub struct struct_ops {}

        impl struct_ops {}
    }

    pub struct OpenExecveSkel<'a> {
        pub obj: libbpf_rs::OpenObject,
        pub struct_ops: execve_types::struct_ops,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
    }

    impl<'a> OpenSkel for OpenExecveSkel<'a> {
        type Output = ExecveSkel<'a>;
        fn load(mut self) -> libbpf_rs::Result<ExecveSkel<'a>> {
            let ret = unsafe { libbpf_sys::bpf_object__load_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            let obj = unsafe { libbpf_rs::Object::from_ptr(self.obj.take_ptr())? };

            Ok(ExecveSkel {
                obj,
                struct_ops: self.struct_ops,
                skel_config: self.skel_config,
                links: ExecveLinks::default(),
            })
        }

        fn open_object(&self) -> &libbpf_rs::OpenObject {
            &self.obj
        }

        fn open_object_mut(&mut self) -> &mut libbpf_rs::OpenObject {
            &mut self.obj
        }
    }
    impl OpenExecveSkel<'_> {
        pub fn progs_mut(&mut self) -> OpenExecveProgsMut<'_> {
            OpenExecveProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn progs(&self) -> OpenExecveProgs<'_> {
            OpenExecveProgs { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> OpenExecveMapsMut<'_> {
            OpenExecveMapsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> OpenExecveMaps<'_> {
            OpenExecveMaps { inner: &self.obj }
        }
    }

    pub struct ExecveMapsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl ExecveMapsMut<'_> {
        pub fn ringbuf(&mut self) -> &mut libbpf_rs::Map {
            self.inner.map_mut("ringbuf").unwrap()
        }

        pub fn rodata(&mut self) -> &mut libbpf_rs::Map {
            self.inner.map_mut("execve_b.rodata").unwrap()
        }
    }

    pub struct ExecveMaps<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl ExecveMaps<'_> {
        pub fn ringbuf(&self) -> &libbpf_rs::Map {
            self.inner.map("ringbuf").unwrap()
        }

        pub fn rodata(&self) -> &libbpf_rs::Map {
            self.inner.map("execve_b.rodata").unwrap()
        }
    }

    pub struct ExecveProgs<'a> {
        inner: &'a libbpf_rs::Object,
    }

    impl ExecveProgs<'_> {
        pub fn detect_execve(&self) -> &libbpf_rs::Program {
            self.inner.prog("detect_execve").unwrap()
        }
    }

    pub struct ExecveProgsMut<'a> {
        inner: &'a mut libbpf_rs::Object,
    }

    impl ExecveProgsMut<'_> {
        pub fn detect_execve(&mut self) -> &mut libbpf_rs::Program {
            self.inner.prog_mut("detect_execve").unwrap()
        }
    }

    #[derive(Default)]
    pub struct ExecveLinks {
        pub detect_execve: Option<libbpf_rs::Link>,
    }

    pub struct ExecveSkel<'a> {
        pub obj: libbpf_rs::Object,
        struct_ops: execve_types::struct_ops,
        skel_config: libbpf_rs::__internal_skel::ObjectSkeletonConfig<'a>,
        pub links: ExecveLinks,
    }

    unsafe impl Send for ExecveSkel<'_> {}
    unsafe impl Sync for ExecveSkel<'_> {}

    impl Skel for ExecveSkel<'_> {
        fn object(&self) -> &libbpf_rs::Object {
            &self.obj
        }

        fn object_mut(&mut self) -> &mut libbpf_rs::Object {
            &mut self.obj
        }

        fn attach(&mut self) -> libbpf_rs::Result<()> {
            let ret = unsafe { libbpf_sys::bpf_object__attach_skeleton(self.skel_config.get()) };
            if ret != 0 {
                return Err(libbpf_rs::Error::from_raw_os_error(-ret));
            }

            self.links = ExecveLinks {
                detect_execve: core::ptr::NonNull::new(self.skel_config.prog_link_ptr(0)?)
                    .map(|ptr| unsafe { libbpf_rs::Link::from_ptr(ptr) }),
            };

            Ok(())
        }
    }
    impl ExecveSkel<'_> {
        pub fn progs_mut(&mut self) -> ExecveProgsMut<'_> {
            ExecveProgsMut {
                inner: &mut self.obj,
            }
        }

        pub fn progs(&self) -> ExecveProgs<'_> {
            ExecveProgs { inner: &self.obj }
        }

        pub fn maps_mut(&mut self) -> ExecveMapsMut<'_> {
            ExecveMapsMut {
                inner: &mut self.obj,
            }
        }

        pub fn maps(&self) -> ExecveMaps<'_> {
            ExecveMaps { inner: &self.obj }
        }

        pub fn struct_ops_raw(&self) -> *const execve_types::struct_ops {
            &self.struct_ops
        }

        pub fn struct_ops(&self) -> &execve_types::struct_ops {
            &self.struct_ops
        }
    }

    const DATA: &[u8] = &[
        127, 69, 76, 70, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 247, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0,
        0, 64, 0, 10, 0, 1, 0, 0, 46, 115, 116, 114, 116, 97, 98, 0, 46, 115, 121, 109, 116, 97,
        98, 0, 116, 112, 47, 115, 121, 115, 99, 97, 108, 108, 115, 47, 115, 121, 115, 95, 101, 110,
        116, 101, 114, 95, 101, 120, 101, 99, 118, 101, 0, 46, 109, 97, 112, 115, 0, 46, 114, 111,
        100, 97, 116, 97, 0, 108, 105, 99, 101, 110, 115, 101, 0, 101, 120, 101, 99, 118, 101, 46,
        98, 112, 102, 46, 99, 0, 76, 66, 66, 48, 95, 50, 0, 100, 101, 116, 101, 99, 116, 95, 101,
        120, 101, 99, 118, 101, 46, 95, 95, 95, 95, 102, 109, 116, 0, 76, 66, 66, 48, 95, 51, 0,
        100, 101, 116, 101, 99, 116, 95, 101, 120, 101, 99, 118, 101, 0, 114, 105, 110, 103, 98,
        117, 102, 0, 95, 108, 105, 99, 101, 110, 115, 101, 0, 46, 114, 101, 108, 116, 112, 47, 115,
        121, 115, 99, 97, 108, 108, 115, 47, 115, 121, 115, 95, 101, 110, 116, 101, 114, 95, 101,
        120, 101, 99, 118, 101, 0, 46, 66, 84, 70, 0, 46, 66, 84, 70, 46, 101, 120, 116, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0,
        0, 4, 0, 241, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 81, 0, 0, 0, 0, 0, 3, 0, 136, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88, 0, 0, 0, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0,
        0, 0, 0, 0, 0, 110, 0, 0, 0, 0, 0, 3, 0, 216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 117, 0, 0, 0, 18,
        0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 0, 0, 0, 0, 0, 0, 0, 131, 0, 0, 0, 17, 0, 4, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 139, 0, 0, 0, 17, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 4, 0, 0, 0, 0, 0, 0, 0, 191, 23, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 14, 0, 0, 0, 191, 9, 0,
        0, 0, 0, 0, 0, 183, 6, 0, 0, 0, 0, 0, 0, 24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        183, 2, 0, 0, 4, 2, 0, 0, 183, 3, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 131, 0, 0, 0, 191, 8, 0,
        0, 0, 0, 0, 0, 85, 8, 6, 0, 0, 0, 0, 0, 24, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        183, 2, 0, 0, 29, 0, 0, 0, 133, 0, 0, 0, 6, 0, 0, 0, 183, 6, 0, 0, 1, 0, 0, 0, 5, 0, 10, 0,
        0, 0, 0, 0, 119, 9, 0, 0, 32, 0, 0, 0, 99, 152, 0, 0, 0, 0, 0, 0, 121, 115, 16, 0, 0, 0, 0,
        0, 191, 129, 0, 0, 0, 0, 0, 0, 7, 1, 0, 0, 4, 0, 0, 0, 183, 2, 0, 0, 0, 2, 0, 0, 133, 0, 0,
        0, 114, 0, 0, 0, 191, 129, 0, 0, 0, 0, 0, 0, 183, 2, 0, 0, 0, 0, 0, 0, 133, 0, 0, 0, 132,
        0, 0, 0, 191, 96, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 98, 112, 102, 95, 114, 105, 110, 103, 98, 117, 102, 95, 114, 101, 115,
        101, 114, 118, 101, 32, 102, 97, 105, 108, 101, 100, 92, 110, 0, 71, 80, 76, 0, 0, 0, 0, 0,
        0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        0, 6, 0, 0, 0, 159, 235, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 212, 1, 0, 0, 212, 1, 0, 0, 151, 2,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 32, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 27, 0, 0, 0, 5, 0, 0, 0, 0, 0,
        0, 1, 4, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
        0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 2, 0, 0, 4, 16, 0, 0, 0, 25, 0,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 5, 0, 0, 0, 64, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0,
        14, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 10, 0, 0, 0, 50, 0, 0, 0, 3, 0, 0, 4,
        24, 0, 0, 0, 64, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 73, 0, 0, 0, 11, 0, 0, 0, 64, 0, 0, 0,
        83, 0, 0, 0, 13, 0, 0, 0, 128, 0, 0, 0, 92, 0, 0, 0, 0, 0, 0, 8, 12, 0, 0, 0, 98, 0, 0, 0,
        0, 0, 0, 1, 8, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 14, 0, 0, 0, 117, 0, 0, 0, 0,
        0, 0, 1, 1, 0, 0, 0, 8, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 13, 2, 0, 0, 0, 122, 0, 0, 0, 9, 0,
        0, 0, 129, 0, 0, 0, 1, 0, 0, 12, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 17, 0, 0, 0, 4, 0, 0, 0, 29, 0, 0, 0, 143, 0, 0, 0, 0, 0, 0,
        14, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 14, 0, 0, 0, 4, 0, 0, 0,
        4, 0, 0, 0, 165, 0, 0, 0, 0, 0, 0, 14, 20, 0, 0, 0, 1, 0, 0, 0, 100, 2, 0, 0, 1, 0, 0, 15,
        16, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 106, 2, 0, 0, 1, 0, 0, 15, 29, 0, 0, 0,
        19, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 114, 2, 0, 0, 1, 0, 0, 15, 4, 0, 0, 0, 21, 0, 0, 0,
        0, 0, 0, 0, 4, 0, 0, 0, 0, 105, 110, 116, 0, 95, 95, 65, 82, 82, 65, 89, 95, 83, 73, 90,
        69, 95, 84, 89, 80, 69, 95, 95, 0, 116, 121, 112, 101, 0, 109, 97, 120, 95, 101, 110, 116,
        114, 105, 101, 115, 0, 114, 105, 110, 103, 98, 117, 102, 0, 101, 120, 101, 99, 118, 101,
        95, 112, 97, 114, 97, 109, 115, 0, 95, 95, 117, 110, 117, 115, 101, 100, 0, 95, 95, 117,
        110, 117, 115, 101, 100, 50, 0, 102, 105, 108, 101, 110, 97, 109, 101, 0, 95, 95, 117, 54,
        52, 0, 117, 110, 115, 105, 103, 110, 101, 100, 32, 108, 111, 110, 103, 32, 108, 111, 110,
        103, 0, 99, 104, 97, 114, 0, 112, 97, 114, 97, 109, 115, 0, 100, 101, 116, 101, 99, 116,
        95, 101, 120, 101, 99, 118, 101, 0, 100, 101, 116, 101, 99, 116, 95, 101, 120, 101, 99,
        118, 101, 46, 95, 95, 95, 95, 102, 109, 116, 0, 95, 108, 105, 99, 101, 110, 115, 101, 0,
        47, 104, 111, 109, 101, 47, 118, 101, 110, 107, 121, 47, 67, 111, 100, 101, 115, 47, 115,
        105, 109, 112, 108, 101, 95, 98, 112, 102, 47, 115, 114, 99, 47, 98, 112, 102, 47, 101,
        120, 101, 99, 118, 101, 46, 98, 112, 102, 46, 99, 0, 105, 110, 116, 32, 100, 101, 116, 101,
        99, 116, 95, 101, 120, 101, 99, 118, 101, 40, 115, 116, 114, 117, 99, 116, 32, 101, 120,
        101, 99, 118, 101, 95, 112, 97, 114, 97, 109, 115, 42, 32, 112, 97, 114, 97, 109, 115, 41,
        32, 123, 0, 32, 32, 32, 32, 95, 95, 117, 51, 50, 32, 112, 105, 100, 32, 61, 32, 98, 112,
        102, 95, 103, 101, 116, 95, 99, 117, 114, 114, 101, 110, 116, 95, 112, 105, 100, 95, 116,
        103, 105, 100, 40, 41, 32, 62, 62, 32, 51, 50, 59, 0, 32, 32, 32, 32, 115, 116, 114, 117,
        99, 116, 32, 101, 118, 101, 110, 116, 42, 32, 101, 118, 116, 32, 61, 32, 98, 112, 102, 95,
        114, 105, 110, 103, 98, 117, 102, 95, 114, 101, 115, 101, 114, 118, 101, 40, 38, 114, 105,
        110, 103, 98, 117, 102, 44, 32, 115, 105, 122, 101, 111, 102, 40, 115, 116, 114, 117, 99,
        116, 32, 101, 118, 101, 110, 116, 41, 44, 32, 48, 41, 59, 0, 32, 32, 32, 32, 105, 102, 32,
        40, 33, 101, 118, 116, 41, 32, 123, 0, 32, 32, 32, 32, 32, 32, 32, 32, 98, 112, 102, 95,
        112, 114, 105, 110, 116, 107, 40, 34, 98, 112, 102, 95, 114, 105, 110, 103, 98, 117, 102,
        95, 114, 101, 115, 101, 114, 118, 101, 32, 102, 97, 105, 108, 101, 100, 92, 92, 110, 34,
        41, 59, 0, 32, 32, 32, 32, 101, 118, 116, 45, 62, 112, 105, 100, 32, 61, 32, 112, 105, 100,
        59, 0, 32, 32, 32, 32, 98, 112, 102, 95, 112, 114, 111, 98, 101, 95, 114, 101, 97, 100, 95,
        117, 115, 101, 114, 95, 115, 116, 114, 40, 101, 118, 116, 45, 62, 102, 105, 108, 101, 110,
        97, 109, 101, 44, 32, 115, 105, 122, 101, 111, 102, 40, 101, 118, 116, 45, 62, 102, 105,
        108, 101, 110, 97, 109, 101, 41, 44, 32, 112, 97, 114, 97, 109, 115, 45, 62, 102, 105, 108,
        101, 110, 97, 109, 101, 41, 59, 0, 32, 32, 32, 32, 98, 112, 102, 95, 114, 105, 110, 103,
        98, 117, 102, 95, 115, 117, 98, 109, 105, 116, 40, 101, 118, 116, 44, 32, 48, 41, 59, 0,
        125, 0, 46, 109, 97, 112, 115, 0, 46, 114, 111, 100, 97, 116, 97, 0, 108, 105, 99, 101,
        110, 115, 101, 0, 116, 112, 47, 115, 121, 115, 99, 97, 108, 108, 115, 47, 115, 121, 115,
        95, 101, 110, 116, 101, 114, 95, 101, 120, 101, 99, 118, 101, 0, 0, 0, 0, 0, 0, 159, 235,
        1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 20, 0, 0, 0, 204, 0, 0, 0, 224, 0, 0, 0, 0, 0,
        0, 0, 8, 0, 0, 0, 122, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 122, 2,
        0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 174, 0, 0, 0, 224, 0, 0, 0, 0, 92, 0, 0, 8, 0, 0, 0, 174, 0,
        0, 0, 18, 1, 0, 0, 17, 96, 0, 0, 32, 0, 0, 0, 174, 0, 0, 0, 68, 1, 0, 0, 25, 100, 0, 0, 80,
        0, 0, 0, 174, 0, 0, 0, 148, 1, 0, 0, 9, 104, 0, 0, 88, 0, 0, 0, 174, 0, 0, 0, 164, 1, 0, 0,
        9, 108, 0, 0, 136, 0, 0, 0, 174, 0, 0, 0, 18, 1, 0, 0, 44, 96, 0, 0, 144, 0, 0, 0, 174, 0,
        0, 0, 217, 1, 0, 0, 14, 120, 0, 0, 152, 0, 0, 0, 174, 0, 0, 0, 237, 1, 0, 0, 75, 124, 0, 0,
        160, 0, 0, 0, 174, 0, 0, 0, 237, 1, 0, 0, 34, 124, 0, 0, 176, 0, 0, 0, 174, 0, 0, 0, 237,
        1, 0, 0, 5, 124, 0, 0, 192, 0, 0, 0, 174, 0, 0, 0, 66, 2, 0, 0, 5, 128, 0, 0, 216, 0, 0, 0,
        174, 0, 0, 0, 98, 2, 0, 0, 1, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 32, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 195, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 240, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0,
        1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 248, 1, 0, 0, 0, 0, 0, 0, 232,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 46, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 224, 2, 0, 0,
        0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 52, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        240, 2, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 13, 3, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 148, 0, 0, 0, 9, 0, 0, 0, 64, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 3, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
        3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 181, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 3, 0, 0, 0, 0, 0, 0, 131, 4, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 186, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 7, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
}
