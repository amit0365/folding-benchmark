bench-all:
	make bench-nova
	make bench-protostar
	make bench-sonobe

bench-nova:
	cd nova && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot

bench-protostar:
	make bench-halo2lib_bctv
	make bench-halo2lib_cyclefold

bench-halo2lib_bctv:
	cd protostar && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot 

bench-halo2lib_cyclefold:
	cd protostar && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot  

bench-sonobe:
	cd sonobe && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot

