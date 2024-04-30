bench-all:
	make bench-nova
	make bench-protostar
	make bench-sonobe

bench-nova:
	cd nova && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot --release

bench-protostar:
	bench-halo2lib_bctv
	bench-halo2lib_cyclefold

bench-halo2lib_bctv:
	cd protostar && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot --release --features nightly-features

bench-halo2lib_cyclefold:
	cd protostar && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot --release --features nightly-features 

bench-sonobe:
	cd sonobe/sha2-chain && RUSTFLAGS="-C target-cpu=native" cargo bench --bench minroot --release

