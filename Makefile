bench-all:
	make bench-nova
	make bench-protostar
	make bench-sonobe

bench-nova:
	cd nova && RUSTFLAGS="-C target-cpu=native" cargo bench minroot --release

bench-protostar:
	cd protostar && RUSTFLAGS="-C target-cpu=native" cargo bench minroot --release --features nightly-features


bench-sonobe:
	cd sonobe/sha2-chain && RUSTFLAGS="-C target-cpu=native" cargo bench minroot --release

