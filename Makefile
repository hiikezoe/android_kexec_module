kexec_module-objs +=		\
	kexec.o			\
	msm_kexec.o		\
	machine_kexec.o		\
	proc-v7.o		\
	relocate_kernel.o	\
	module.o		\

obj-m = kexec_module.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

