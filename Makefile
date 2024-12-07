bench-all:
	make bench-nova
	make bench-protostar
	make bench-sonobe

bench-nova:
	cd nova && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot
	cd nova && RUSTFLAGS="-C target-cpu=native" cargo bench --bench hashchain

bench-protostar:
	make bench-halo2lib_bctv
	make bench-halo2lib_cyclefold
	make bench-custom_cyclefold

bench-halo2lib_bctv:
	cd protostar/halo2lib_bctv && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot 

bench-halo2lib_cyclefold:
	cd protostar/halo2lib_cyclefold && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot 

bench-custom_cyclefold:
	cd protostar/custom_cyclefold && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot 

bench-sonobe:
	cd sonobe && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot

